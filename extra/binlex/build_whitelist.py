#!/usr/bin/env python3
"""
Binlex Whitelist Generator for Windows Systems
Scans common Windows system, runtime, and utility directories,
running Binlex on each file to build a custom benign traits whitelist.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

def load_config(config_path):
    p = Path(config_path)
    if not p.exists():
        print(f"[-] Config file not found at {config_path}")
        sys.exit(1)
    with open(p, "r") as f:
        return json.load(f)

def find_files(directories, extensions, max_size):
    targets = []
    print("[*] Scanning directories for target files...")
    for directory in directories:
        expanded = os.path.expandvars(directory)
        dir_path = Path(expanded)
        if not dir_path.exists():
            print(f"[-] Directory does not exist, skipping: {dir_path}")
            continue
        print(f"[*] Scanning: {dir_path}")
        try:
            for p in dir_path.rglob("*"):
                try:
                    if p.is_file() and p.suffix.lower() in extensions:
                        size = p.stat().st_size
                        if 0 < size <= max_size:
                            targets.append(p)
                except OSError:
                    continue
        except Exception as e:
            print(f"[-] Error scanning {dir_path}: {e}")
            continue
    return targets

def run_binlex(binlex_path, file_path, use_docker=False, docker_image="c3rb3ru5d3d53c/binlex:latest", mount_path=""):
    if use_docker:
        posix_file_path = Path(file_path).as_posix()
        posix_mount_path = Path(mount_path).as_posix()
        if posix_file_path.startswith(posix_mount_path):
            container_file_path = posix_file_path.replace(posix_mount_path, "/storage", 1)
        else:
            container_file_path = posix_file_path
        
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{posix_mount_path}:/storage:ro",
            str(docker_image),
            "binlex", "-i", str(container_file_path)
        ]
    else:
        cmd = [str(binlex_path), "-i", str(file_path)]

    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = p.communicate()
        if p.returncode != 0:
            return []
        
        traits = []
        for line in stdout.decode(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                trait_data = json.loads(line)
                pattern = trait_data.get("chromosome", {}).get("pattern")
                if pattern:
                    traits.append(pattern)
            except Exception:
                continue
        return traits
    except FileNotFoundError:
        print(f"[-] Command/Binary not found. Please verify paths or docker installation.")
        sys.exit(1)
    except Exception:
        # Suppress errors for single files to keep execution clean
        return []

def main():
    parser = argparse.ArgumentParser(description="Generate Binlex Whitelist from Windows System files.")
    parser.add_argument("-c", "--config", default="whitelist_config.json", help="Path to config file.")
    args = parser.parse_args()

    config = load_config(args.config)
    binlex_path = config.get("binlex_path", "binlex.exe")
    use_docker = binlex_path.lower() == "docker"
    docker_image = config.get("docker_image", "c3rb3ru5d3d53c/binlex:latest")
    mount_path = config.get("mount_path", "")

    output_file = Path(config.get("output_file", "benign_traits.txt"))
    max_size = config.get("max_file_size_bytes", 52428800)
    extensions = [ext.lower() for ext in config.get("extensions", [".dll", ".exe"])]
    directories = config.get("directories", [])

    targets = find_files(directories, extensions, max_size)
    total_files = len(targets)
    print(f"[+] Found {total_files} candidate files to process.")

    if total_files == 0:
        print("[-] No files found matching criteria. Exiting.")
        sys.exit(0)

    unique_traits = set()
    processed_count = 0

    print("[*] Processing files and extracting benign traits...")
    for target in targets:
        processed_count += 1
        traits = run_binlex(
            binlex_path=binlex_path,
            file_path=target,
            use_docker=use_docker,
            docker_image=docker_image,
            mount_path=mount_path
        )
        if traits:
            unique_traits.update(traits)
        
        if processed_count % 50 == 0 or processed_count == total_files:
            print(f"[*] Processed {processed_count}/{total_files} files (Collected {len(unique_traits)} unique traits)")

    print(f"[*] Writing {len(unique_traits)} unique traits to {output_file}...")
    try:
        with open(output_file, "w") as f:
            for trait in sorted(unique_traits):
                f.write(trait + "\n")
        print(f"[+] Whitelist successfully built: {output_file}")
    except Exception as e:
        print(f"[-] Failed writing whitelist to file: {e}")

if __name__ == "__main__":
    main()
