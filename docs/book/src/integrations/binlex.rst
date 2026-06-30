======
Binlex
======

Binlex (Binary Genetic Traits Lexer) extracts genetic traits (wildcarded instructions, basic blocks, and functions) from analyzed binaries, allowing analysts to identify code similarity and generate YARA signatures.

Option C (shared disk volume mount with execution via ``docker exec``) is the recommended high-performance approach when running CAPEv2 and Docker on the same physical host.

Docker Installation
===================

1. Create a dedicated directory for the Binlex container configuration. It is recommended to place this in CAPE's auxiliary extras folder, e.g., ``/opt/CAPEv2/extra/binlex/``::

    sudo mkdir -p /opt/CAPEv2/extra/binlex
    cd /opt/CAPEv2/extra/binlex

2. Create and configure your ``compose.yml`` file in this directory to mount the CAPEv2 host storage directory (typically ``/opt/CAPEv2/storage``) as read-only (``:ro``) inside the container at ``/storage``:

Example ``compose.yml``::

    version: "3.8"

    services:
      binlex-server:
        image: c3rb3ru5d3d53c/binlex:latest
        container_name: binlex-server
        restart: always
        volumes:
          - /opt/CAPEv2/storage:/storage:ro

3. Start the container from within the configuration directory::

    docker compose up -d

Configuration in CAPEv2
=======================

Enable and configure the processing module in ``conf/processing.conf`` under the ``[binlex]`` section::

    [binlex]
    enabled = yes
    # Path/command for docker binary
    docker_binary = docker
    # Name of the docker container
    container_name = binlex-server
    # Prefix mapping translation
    host_storage_prefix = /opt/CAPEv2/storage
    container_storage_prefix = /storage

Ensuring Binlex Docker Container Starts with CAPE
=================================================

There are two primary methods to ensure the Binlex Docker container is running when CAPE starts:

Method 1: Docker Restart Policy (Recommended)
---------------------------------------------
By setting ``restart: always`` (or ``restart: unless-stopped``) in your ``compose.yml`` (as shown in the example compose file above), the Docker daemon will automatically launch the container when the system boots, independent of CAPE's services. Ensure the Docker daemon itself is enabled to start on boot::

    sudo systemctl enable docker

Method 2: Systemd Integration
-----------------------------
If you want to explicitly tie the lifecycle of the ``binlex-server`` container to CAPE's processing service, you can edit the CAPE systemd service file (typically ``/etc/systemd/system/cape-processor.service``) to ensure the Docker container starts beforehand:

1. Add ``docker.service`` to the unit dependencies.
2. Use ``ExecStartPre`` to automatically start the container if it's stopped.

For example, update ``cape-processor.service`` as follows::

    [Unit]
    Description=CAPE report processor
    ...
    Requires=docker.service
    After=docker.service cape-rooter.service

    [Service]
    ...
    # Start binlex-server container if it is not already running
    ExecStartPre=-/usr/bin/docker start binlex-server
    ExecStart=/etc/poetry/bin/poetry run python utils/process.py
    ...

Run ``sudo systemctl daemon-reload`` and restart the processor after modifying the unit file.

Building a Benign Whitelist Library (Tuning)
============================================

To prevent common Windows libraries and standard code runtime files from flooding the results with false-positive traits, you should build a benign traits whitelist library on a clean Windows machine:

1. Download the ``binlex.exe`` binary from the official GitHub releases and place it alongside the builder script.
2. In CAPE's ``extra/binlex/`` directory, customize the ``whitelist_config.json`` configuration file to specify target folders (e.g., ``C:\Windows\System32``, runtime folders), search file extensions, and the path to ``binlex.exe``.
3. Execute the generator script on the clean Windows machine::

    python build_whitelist.py -c whitelist_config.json

4. This processes the designated directories and outputs a deduplicated list of benign patterns in ``benign_traits.txt``. Copy this file to your CAPEv2 server and configure its path under the whitelist path section of your config or modules.

Option B: Mounting and Scanning a VM's QCOW2 Disk directly on Linux
--------------------------------------------------------------------
If you already have a QCOW2 virtual disk image of your clean VM template on your CAPEv2 host, you can mount it directly to a local directory on Linux and run ``build_whitelist.py`` using the host's native (Linux) ``binlex`` binary.

1. Install QEMU block device utilities and load the network block device (NBD) driver::

    sudo apt-get install qemu-utils
    sudo modprobe nbd max_part=8

2. Connect the QCOW2 virtual disk image to an NBD interface::

    sudo qemu-nbd --connect=/dev/nbd0 /path/to/clean_windows.qcow2

3. Identify the main Windows NTFS partition (usually partition 2 or 3) and mount it as read-only (``-o ro``) to a mount point::

    sudo fdisk -l /dev/nbd0
    sudo mkdir -p /mnt/windows_vm
    sudo mount -o ro /dev/nbd0p2 /mnt/windows_vm

4. Copy the ``extra/binlex/build_whitelist.py`` and ``whitelist_config.json`` to a working directory on your host. 
   - Set ``binlex_path`` to ``"docker"`` to execute Binlex inside the container.
   - Set ``mount_path`` to match your local VM mount point (e.g., ``/mnt/windows_vm``).
   - Set ``docker_image`` to your target Binlex image.
   - Update the ``directories`` array to match the mounted filesystem paths.

   Example ``whitelist_config.json`` configuration::

    {
      "binlex_path": "docker",
      "docker_image": "c3rb3ru5d3d53c/binlex:latest",
      "mount_path": "/mnt/windows_vm",
      "output_file": "benign_traits.txt",
      "max_file_size_bytes": 52428800,
      "extensions": [".dll", ".exe", ".sys", ".ocx"],
      "directories": [
        "/mnt/windows_vm/Windows/System32",
        "/mnt/windows_vm/Windows/SysWOW64",
        "/mnt/windows_vm/Program Files/dotnet"
      ]
    }

5. Execute the script to generate the whitelist directly on the CAPEv2 host (it will invoke docker containers for files on-demand translating mount paths)::

    python3 build_whitelist.py -c whitelist_config.json

Option C: Self-Contained QCOW2 Whitelist Builder Docker Image
-------------------------------------------------------------
For a completely automated, zero-dependency execution, you can build and run a self-contained Whitelist Builder Docker image. This image mounts the QCOW2 virtual disk image directly inside the container, automatically discovers the Windows partition, runs the Python scanner/disassembler, and cleans up the devices.

1. Ensure the host's kernel has the Network Block Device (NBD) module loaded::

    sudo modprobe nbd max_part=8

2. Build the Docker image from the ``extra/binlex/`` directory::

    cd extra/binlex/
    docker build -t binlex-whitelist-builder .

3. Run the container in privileged mode (required for NBD connection and filesystem mounting) mapping the host's QCOW2 file path to ``/input/image.qcow2`` and a folder for the resulting output::

    docker run --privileged --rm \
      -v /path/to/clean_windows.qcow2:/input/image.qcow2:ro \
      -v $(pwd):/output \
      binlex-whitelist-builder

4. The container's entrypoint script will automatically connect the image, mount the Windows partition read-only to ``/storage``, run the trait scanner, output ``benign_traits.txt`` to your current host directory, and unmount the block devices.


How it Works
============

1. The CAPEv2 processing pipeline triggers the ``BinlexAnalysis`` module during the reporting phase.
2. The module translates the local file path (e.g., ``/opt/CAPEv2/storage/analyses/1234/binary.exe``) to the container path (e.g., ``/storage/analyses/1234/binary.exe``).
3. It executes the disassembler via ``docker exec binlex-server binlex -i <container_path>``.
4. Extracted traits are returned to CAPEv2, where the Web UI renders an interactive dashboard and live YARA rule builder.
