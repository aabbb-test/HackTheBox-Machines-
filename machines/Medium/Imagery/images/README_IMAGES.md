# Images Directory

⚠️ **ACTION REQUIRED**: The following images need to be copied from the main branch to this directory.

## Required Images

The images are currently in the root of the `main` branch:

1. aesdecrypt.png
2. burp.png
3. burp2.png
4. burp3.png
5. db_results.png
6. dirseach.png
7. gettingRootFlag.png
8. login.png
9. markpass.png
10. nmap.png
11. nuclei.png
12. php_receiver.png
13. poc.png
14. pwn.png
15. rev_shell.png
16. testuserpass.png
17. user_flag.png

## How to Copy Images

### Option 1: Using Git Commands

```bash
# Save your current work
git stash

# Switch to main branch
git checkout main

# Copy all PNG files
cp *.png machines/Medium/Imagery/images/

# Switch back to the PR branch
git checkout copilot/create-guide-for-machine

# Restore stashed changes if any
git stash pop

# Add the images
git add machines/Medium/Imagery/images/*.png
```

### Option 2: Manual Copy

1. Navigate to the repository on GitHub
2. Switch to the `main` branch
3. Download each PNG file
4. Place them in this directory (`machines/Medium/Imagery/images/`)

## Verification

After copying, verify all 17 images are present:

```bash
ls -1 machines/Medium/Imagery/images/*.png | wc -l
# Should output: 17
```

Once the images are in place, the writeup in `../README.md` will display them correctly.
