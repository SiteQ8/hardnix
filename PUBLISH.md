# 🚀 Publishing to GitHub

## Step 1: Create repo on GitHub
Go to https://github.com/new and create a repo called `hardnix`

## Step 2: Initialize and push

```bash
cd hardnix/
git init
git add .
git commit -m "feat: initial release of HardNix v1.0.0

- 12 security audit modules (100+ checks)
- Scoring system with letter grades
- Terminal, JSON, and HTML output formats
- GTFOBins-aware SUID detection
- Container escape vector checks
- Zero external dependencies"

git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/hardnix.git
git push -u origin main
```

## Step 3: Add GitHub topics
Go to your repo → click ⚙️ → add topics:
`security`, `linux`, `bash`, `hardening`, `pentest`, `red-team`, `audit`, `suid`, `cis-benchmark`

## Step 4: Create a release
```bash
git tag -a v1.0.0 -m "HardNix v1.0.0 — Initial Release"
git push origin v1.0.0
```
Then on GitHub: Releases → Create Release → pick tag v1.0.0

## Step 5: Optional — Submit to awesome lists
- https://github.com/topics/security
- awesome-security on GitHub
- r/netsec, r/AskNetsec
