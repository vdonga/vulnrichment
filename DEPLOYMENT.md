# 🚀 GitHub Pages Deployment Guide

This guide will help you deploy the CISA Vulnrichment Web Viewer to GitHub Pages.

## Option 1: Automatic Deployment (Recommended)

The repository includes a GitHub Actions workflow that will automatically build and deploy your site.

### Steps:

1. **Enable GitHub Pages in Repository Settings**
   - Go to your repository: https://github.com/vdonga/vulnrichment
   - Click **Settings** → **Pages**
   - Under "Build and deployment" → "Source", select **GitHub Actions**
   - Click **Save**

2. **Push Your Changes**
   ```bash
   git add .
   git commit -m "Add web viewer for CVE data"
   git push origin main
   ```

3. **Wait for Deployment**
   - Go to the **Actions** tab in your repository
   - You'll see a workflow called "Deploy to GitHub Pages" running
   - Wait for it to complete (usually 1-2 minutes)

4. **Access Your Site**
   - Your site will be available at: **https://vdonga.github.io/vulnrichment/**
   - The URL will also appear in the **Actions** workflow output

### What the Workflow Does:
- Automatically generates the CVE index (limited to 5000 recent CVEs to keep the site fast)
- Builds and deploys to GitHub Pages
- Runs every time you push to the main/develop branch

## Option 2: Manual Deployment

If you prefer to deploy manually or want to include all CVEs:

### Steps:

1. **Generate the Index File**
   ```bash
   # For all CVEs (warning: creates a large ~150MB file)
   python3 generate_index.py
   
   # Or limit to recent CVEs (recommended for better performance)
   python3 generate_index.py 5000
   ```

2. **Enable GitHub Pages**
   - Go to **Settings** → **Pages**
   - Under "Build and deployment" → "Source", select **Deploy from a branch**
   - Select branch: **main** (or **develop**)
   - Select folder: **/docs**
   - Click **Save**

3. **Commit and Push**
   ```bash
   git add docs/cve-index.json
   git commit -m "Add CVE index"
   git push origin main
   ```

4. **Wait for Deployment**
   - GitHub will automatically deploy your site
   - Check the **Actions** tab for progress
   - Your site will be live at: **https://vdonga.github.io/vulnrichment/**

## Testing Locally

Before deploying, you can test the site locally:

1. **Generate a test index**
   ```bash
   python3 generate_index.py 100
   ```

2. **Start a local web server**
   ```bash
   cd docs
   python3 -m http.server 8000
   ```

3. **Open in browser**
   - Navigate to: http://localhost:8000
   - Test the search, filters, and pagination

## Customizing the Deployment

### Change the Number of CVEs

Edit `.github/workflows/pages.yml` and change the limit:

```yaml
- name: Generate CVE Index
  run: |
    echo "Generating CVE index..."
    python3 generate_index.py 10000  # Change this number
```

### Deploy All CVEs

If you want to deploy all CVEs (warning: large file size):

```yaml
- name: Generate CVE Index
  run: |
    echo "Generating full CVE index..."
    python3 generate_index.py  # Remove the limit
```

## Troubleshooting

### Site Not Loading Data

**Problem**: The table shows "No CVEs found" or loading error.

**Solution**: 
1. Check if `docs/cve-index.json` exists
2. Regenerate the index: `python3 generate_index.py 100`
3. Verify the file is not empty: `ls -lh docs/cve-index.json`

### GitHub Actions Failing

**Problem**: Workflow fails in Actions tab.

**Solution**:
1. Go to **Settings** → **Actions** → **General**
2. Under "Workflow permissions", select "Read and write permissions"
3. Check "Allow GitHub Actions to create and approve pull requests"
4. Click **Save**

### 404 Error on GitHub Pages

**Problem**: Site shows 404 error.

**Solution**:
1. Verify GitHub Pages is enabled in Settings
2. Ensure you selected the correct branch and `/docs` folder
3. Wait a few minutes for DNS propagation
4. Check the Actions tab for deployment status

### Site is Too Slow

**Problem**: Site takes a long time to load.

**Solution**: Reduce the number of CVEs in the index:
```bash
python3 generate_index.py 1000
```

## Performance Notes

- **Full Index** (~236k CVEs): ~150-200 MB, may be slow to load
- **5000 CVEs**: ~3-5 MB, good balance of data and performance
- **1000 CVEs**: ~600 KB, very fast loading
- **100 CVEs**: ~70 KB, instant loading (good for testing)

## Next Steps

After deployment:
1. Share your site URL: `https://vdonga.github.io/vulnrichment/`
2. Customize the styling in `docs/styles.css`
3. Add more features to `docs/app.js`
4. Set up a custom domain (optional)

## Support

- **GitHub Pages Documentation**: https://docs.github.com/en/pages
- **GitHub Actions Documentation**: https://docs.github.com/en/actions
- **Issues**: Open an issue in your repository for help

---

**Your site will be live at**: https://vdonga.github.io/vulnrichment/

Happy deploying! 🎉
