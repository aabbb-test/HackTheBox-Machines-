# Setup Instructions for Imagery Writeup

## Moving Images from Main Branch

The images for this writeup are currently in the root of the `main` branch and need to be moved to the `machines/Medium/Imagery/images/` directory.

### Required Images

The following images need to be copied:

- aesdecrypt.png
- burp.png
- burp2.png
- burp3.png
- db_results.png
- dirseach.png
- gettingRootFlag.png
- login.png
- markpass.png
- nmap.png
- nuclei.png
- php_receiver.png
- poc.png
- pwn.png
- rev_shell.png
- testuserpass.png
- user_flag.png

### Automated Setup Script

Run this command to copy all images from the main branch:

```bash
#!/bin/bash

# Ensure we're in the repository root
cd "$(git rev-parse --show-toplevel)"

# Image files to copy
images=(
    "aesdecrypt.png"
    "burp.png"
    "burp2.png"
    "burp3.png"
    "db_results.png"
    "dirseach.png"
    "gettingRootFlag.png"
    "login.png"
    "markpass.png"
    "nmap.png"
    "nuclei.png"
    "php_receiver.png"
    "poc.png"
    "pwn.png"
    "rev_shell.png"
    "testuserpass.png"
    "user_flag.png"
)

# Destination directory
dest_dir="machines/Medium/Imagery/images"

# Create destination directory if it doesn't exist
mkdir -p "$dest_dir"

# Copy each image from main branch
for img in "${images[@]}"; do
    echo "Copying $img..."
    git show main:"$img" > "$dest_dir/$img" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✓ Copied $img"
    else
        echo "  ✗ Failed to copy $img (file may not exist in main branch)"
    fi
done

echo ""
echo "Done! All available images have been copied to $dest_dir"
```

### Manual Setup

If you prefer to copy images manually:

1. Checkout the main branch:
   ```bash
   git checkout main
   ```

2. Copy all PNG files to the images directory:
   ```bash
   cp *.png machines/Medium/Imagery/images/
   ```

3. Return to your working branch:
   ```bash
   git checkout copilot/create-guide-for-machine
   ```

4. Add the images:
   ```bash
   git add machines/Medium/Imagery/images/*.png
   ```

## Directory Structure

After setup, your directory structure should look like this:

```
machines/
└── Medium/
    └── Imagery/
        ├── README.md          # Main walkthrough guide
        ├── SETUP.md          # This file
        ├── images/
        │   ├── aesdecrypt.png
        │   ├── burp.png
        │   ├── burp2.png
        │   ├── burp3.png
        │   ├── db_results.png
        │   ├── dirseach.png
        │   ├── gettingRootFlag.png
        │   ├── login.png
        │   ├── markpass.png
        │   ├── nmap.png
        │   ├── nuclei.png
        │   ├── php_receiver.png
        │   ├── poc.png
        │   ├── pwn.png
        │   ├── rev_shell.png
        │   ├── testuserpass.png
        │   └── user_flag.png
        └── raw-logs/
            ├── dirsearch.txt
            ├── instructions.txt
            ├── nmap.txt
            ├── nuclei.txt
            └── php_receiver.php
```

## Verification

After copying the images, verify they're all present:

```bash
ls -la machines/Medium/Imagery/images/
```

You should see 17 PNG files.
