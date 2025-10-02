#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import stat

def ask(prompt, default=None, required=False):
    if default:
        prompt = f"{prompt} [{default}]: "
    else:
        prompt = f"{prompt}: "
    while True:
        try:
            val = input(prompt).strip()
        except EOFError:
            # Handle case where no input is available (non-interactive mode)
            if default is not None:
                print(f"\n[i] Using default value: {default}")
                return default
            elif not required:
                print("\n[i] Using empty value")
                return ""
            else:
                print("\n[!] Required input not available in non-interactive mode")
                raise
        if not val and default is not None:
            return default
        if val or not required:
            return val
        print("This value is required.")

def ensure_git_exists():
    if shutil.which("git") is None:
        print("Error: git is not installed or not in PATH. Install Git and try again.")
        sys.exit(1)

def configure_git_longpaths():
    """Configure Git to handle long paths on Windows."""
    if os.name == "nt":
        try:
            # Enable long path support for the current repository
            subprocess.run(["git", "config", "--global", "core.longpaths", "true"], 
                         check=True, capture_output=True)
            print("[i] Enabled Git long path support for Windows")
        except subprocess.CalledProcessError as e:
            print(f"[!] Warning: Could not configure Git long paths: {e}")
            print("[i] You may encounter issues with long file paths")

def set_permissions_unix(path, perm_str):
    try:
        os.chmod(path, int(perm_str, 8))
        print(f"[✔] Permissions set to {perm_str}")
    except Exception as e:
        print("[✖] Error setting permissions:", e)

def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clone_repo(repo_url, branch="main", target=".", perm="755"):
    """Clone a Git repository to the target folder with proper permissions.
    
    Args:
        repo_url: URL of the repository to clone
        branch: Branch to clone (default: main)
        target: Target directory where the repository will be cloned
        perm: Permissions to set (Unix-like systems only)
    """
    ensure_git_exists()
    configure_git_longpaths()

    # Normalize target path
    target = os.path.expanduser(target)
    target = os.path.abspath(target)
    
    # Extract repository name from URL if target is a directory
    repo_name = os.path.splitext(os.path.basename(repo_url.rstrip('/')))[0]
    clone_target = os.path.join(target, repo_name) if os.path.isdir(target) else target

    # Handle existing target folder
    if os.path.exists(clone_target) and os.listdir(clone_target):
        ans = ask(f"Target '{clone_target}' exists and is not empty. Remove and continue? (y/n)", default="n")
        if ans.lower() != "y":
            print("Aborting.")
            sys.exit(0)
        else:
            shutil.rmtree(clone_target, onerror=remove_readonly)
            print(f"[i] Removed existing folder {clone_target}")

    # Create parent directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(clone_target)), exist_ok=True)

    # Clone repository
    clone_cmd = ["git", "clone"]
    if branch:
        clone_cmd.extend(["--branch", branch])
    clone_cmd.extend([repo_url, clone_target])

    try:
        subprocess.run(clone_cmd, check=True)
        print("[✔] Repository cloned successfully.")
    except subprocess.CalledProcessError as e:
        print("[✖] Error cloning repository:", e)
        sys.exit(1)

    # Set permissions
    if os.name != "nt":
        set_permissions_unix(target, perm)
    else:
        print("[i] Running on Windows: setting Full Control for current user via icacls")
        user = os.getlogin()
        icacls_cmd = ["icacls", target, "/grant", f"{user}:F", "/T", "/C"]
        try:
            subprocess.run(icacls_cmd, check=True)
            print(f"[✔] Full control granted to {user} on {target}")
        except subprocess.CalledProcessError as e:
            print("[✖] Error setting Windows ACL:", e)
            print("[i] You may need to run the script as Administrator.")
