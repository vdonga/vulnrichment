# Quick Start Guide

## 🎯 What You Have

A complete web application that displays CVE data from your repository in a beautiful, searchable table.

## 📁 Files Created

```
├── docs/
│   ├── index.html          # Main web page
│   ├── styles.css          # Styling
│   ├── app.js             # JavaScript functionality
│   ├── cve-index.json     # Generated data (not in git)
│   └── README.md          # Documentation
├── .github/
│   └── workflows/
│       └── pages.yml      # Auto-deployment workflow
├── generate_index.py      # Script to create index
├── DEPLOYMENT.md          # Full deployment guide
└── .gitignore            # Ignore large files
```

## 🚀 Quick Deploy (3 steps)

### 1. Generate the Index
```bash
# Test with 100 CVEs
python3 generate_index.py 100

# Or use more CVEs (5000 recommended)
python3 generate_index.py 5000
```

### 2. Enable GitHub Pages
- Go to: https://github.com/vdonga/vulnrichment/settings/pages
- Source: **GitHub Actions**
- Save

### 3. Push Your Code
```bash
git add .
git commit -m "Add CVE web viewer"
git push origin main
```

**That's it!** Your site will be live at: https://vdonga.github.io/vulnrichment/

## 🧪 Test Locally First

```bash
# Generate test data
python3 generate_index.py 100

# Start local server
cd docs
python3 -m http.server 8000

# Open browser
open http://localhost:8000
```

## 🎨 Customize

### Change Colors
Edit `docs/styles.css`:
```css
:root {
    --primary-color: #0066cc;  /* Your color here */
}
```

### Add More Data
Edit `generate_index.py` to extract additional fields from CVE JSON files.

### Modify Layout
Edit `docs/index.html` to add/remove columns or features.

## 📊 Performance Tips

| CVE Count | File Size | Load Time | Recommendation |
|-----------|-----------|-----------|----------------|
| 100       | ~70 KB    | Instant   | Testing        |
| 1,000     | ~600 KB   | Very fast | Small projects |
| 5,000     | ~3-5 MB   | Fast      | **Recommended** |
| 10,000    | ~6-10 MB  | Good      | Medium projects|
| All (~236k)| ~150 MB  | Slow      | Not recommended|

## ❓ Troubleshooting

**"No CVEs found"**
→ Run: `python3 generate_index.py 100`

**GitHub Actions failing**
→ Settings → Actions → General → Enable "Read and write permissions"

**404 error**
→ Wait 2-3 minutes after enabling GitHub Pages

## 📚 Learn More

- **Full Deployment Guide**: [DEPLOYMENT.md](DEPLOYMENT.md)
- **Web Viewer Docs**: [docs/README.md](docs/README.md)
- **GitHub Pages Docs**: https://pages.github.com

## 🎉 Next Steps

1. ✅ Test locally
2. ✅ Deploy to GitHub Pages
3. 🔗 Share your URL
4. 🎨 Customize styling
5. ⭐ Add more features!

---

**Questions?** Check [DEPLOYMENT.md](DEPLOYMENT.md) for detailed instructions.
