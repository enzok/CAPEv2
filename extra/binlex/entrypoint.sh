#!/bin/bash
set -e

QCOW2_IMAGE="/input/image.qcow2"
MOUNT_DIR="/storage"
NBD_DEV="/dev/nbd0"

if [ ! -f "$QCOW2_IMAGE" ]; then
    echo "[-] QCOW2 image not found at $QCOW2_IMAGE."
    echo "    Please mount your image file into the container at $QCOW2_IMAGE"
    exit 1
fi

if [ ! -b "$NBD_DEV" ]; then
    echo "[-] Network Block Device $NBD_DEV not found inside container."
    echo "    Ensure you run the container with --privileged and the host has 'nbd' module loaded (modprobe nbd max_part=8)."
    exit 1
fi

echo "[*] Connecting $QCOW2_IMAGE to $NBD_DEV..."
qemu-nbd --connect="$NBD_DEV" "$QCOW2_IMAGE"

# Force kernel partition table re-scan
echo "[*] Scanning partition tables on $NBD_DEV..."
partx -av "$NBD_DEV" || true
sleep 2

# Try to find and mount the Windows partition
echo "[*] Searching for Windows partition..."
FOUND_PARTITION=""

# Prepare target candidates: sub-partitions (e.g., nbd0p1) or the base device itself
CANDIDATES=""
for p in ${NBD_DEV}p*; do
    if [ -b "$p" ]; then
        CANDIDATES="$CANDIDATES $p"
    fi
done

# If no partition devices were found, check the base device directly
if [ -z "$CANDIDATES" ]; then
    echo "[*] No partitions detected, trying base device $NBD_DEV..."
    CANDIDATES="$NBD_DEV"
fi

for part in $CANDIDATES; do
    if [ -b "$part" ]; then
        echo "[*] Trying partition/device $part..."
        mkdir -p "$MOUNT_DIR"
        # Try mounting NTFS or standard filesystem read-only
        if mount -o ro "$part" "$MOUNT_DIR" 2>/dev/null; then
            if [ -d "$MOUNT_DIR/Windows/System32" ]; then
                echo "[+] Found Windows installation on $part."
                FOUND_PARTITION="$part"
                break
            else
                umount "$MOUNT_DIR"
            fi
        fi
    fi
done

if [ -z "$FOUND_PARTITION" ]; then
    echo "[-] Could not find a partition containing a Windows installation (/Windows/System32)."
    echo "[*] Disconnecting block device..."
    qemu-nbd --disconnect "$NBD_DEV"
    exit 1
fi

# Run the python whitelist builder script
echo "[*] Running Whitelist Builder..."
python3 /app/build_whitelist.py -c /app/whitelist_config.json

# Cleanup mounts
echo "[*] Cleaning up mounts..."
umount "$MOUNT_DIR"
qemu-nbd --disconnect "$NBD_DEV"
echo "[+] Done!"
