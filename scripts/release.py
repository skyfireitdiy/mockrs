#!/usr/bin/env python3
"""
A script to handle version bumping, committing, and tagging.
"""
import re
import sys
import subprocess
import os


def get_current_version():
    """Get the current version from Cargo.toml."""
    with open("Cargo.toml", "r", encoding="utf-8") as f:
        content = f.read()
        version_match = re.search(
            r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', content, re.M
        )
        if version_match:
            return [int(v) for v in version_match.groups()]
    raise ValueError("Version not found in Cargo.toml")


def update_cargo_toml(version_list):
    """Update the version in Cargo.toml."""
    new_version_str = ".".join(map(str, version_list))
    with open("Cargo.toml", "r", encoding="utf-8") as f:
        content = f.read()

    content = re.sub(
        r'(^version\s*=\s*)"(\d+)\.(\d+)\.(\d+)"',
        rf'\1"{new_version_str}"',
        content,
        count=1,
        flags=re.M,
    )

    with open("Cargo.toml", "w", encoding="utf-8") as f:
        f.write(content)
    return new_version_str


def main():
    """Main function."""
    if len(sys.argv) != 2 or sys.argv[1] not in ["major", "minor", "patch"]:
        print("Usage: python scripts/release.py [major|minor|patch]")
        sys.exit(1)

    print("Running tests...")
    subprocess.run(["cargo", "test"], check=True)
    print("Tests passed.")

    bump_type = sys.argv[1]

    major, minor, patch = get_current_version()

    if bump_type == "major":
        major += 1
        minor = 0
        patch = 0
    elif bump_type == "minor":
        minor += 1
        patch = 0
    else:
        patch += 1

    new_version_str = update_cargo_toml([major, minor, patch])
    print(f"Version bumped to {new_version_str}")

    # Run cargo check to update Cargo.lock without a full build
    print("Updating Cargo.lock...")
    subprocess.run(["cargo", "check"], check=True)

    commit_message = f"chore(release): v{new_version_str}"
    tag_name = f"v{new_version_str}"

    subprocess.run(["git", "add", "Cargo.toml", "Cargo.lock"], check=True)
    commit_env = os.environ.copy()
    commit_env["GIT_AUTHOR_NAME"] = "skyfire"
    commit_env["GIT_AUTHOR_EMAIL"] = "skyfireitdiy@hotmail.com"
    subprocess.run(["git", "commit", "-m", commit_message], check=True, env=commit_env)
    print(f"Committed with message: '{commit_message}'")

    subprocess.run(["git", "tag", tag_name], check=True)
    print(f"Created tag: '{tag_name}'")

    print("Pushing changes to remote...")
    subprocess.run(["git", "push"], check=True)
    subprocess.run(["git", "push", "origin", tag_name], check=True)
    print("Push successful.")


if __name__ == "__main__":
    main()
