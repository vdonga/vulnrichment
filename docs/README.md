# CISA Vulnrichment Web Viewer

A modern, interactive web application for browsing and searching CVE vulnerability data enriched by CISA.

## Features

- 📊 **Tabular Display**: Browse all CVEs in an easy-to-read table format
- 🔍 **Powerful Search**: Search across CVE IDs, descriptions, vendors, and products
- 🎯 **Advanced Filtering**: Filter by year, severity, exploitation status, and KEV status
- 📱 **Responsive Design**: Works seamlessly on desktop and mobile devices
- 🌓 **Dark Mode**: Automatic dark mode support based on system preferences
- ⚡ **Fast Performance**: Efficient data loading and pagination
- 🔗 **No Backend Required**: Pure client-side application, perfect for GitHub Pages

## Setup Instructions

### 1. Generate the Index File

Before deploying the web app, you need to generate an index of all CVE files:

```bash
# Generate index for all CVEs
python3 generate_index.py

# Or generate a limited index for testing (e.g., first 1000 CVEs)
python3 generate_index.py 1000
```

This will create `docs/cve-index.json` containing metadata from all CVE files.

**Note**: The full index file will be quite large (100-200 MB). For testing or if you want a smaller deployment, use the limited option.

### 2. Enable GitHub Pages

1. Go to your repository on GitHub
2. Click **Settings** → **Pages**
3. Under "Source", select **Deploy from a branch**
4. Choose the branch (e.g., `main` or `develop`) and select `/docs` as the folder
5. Click **Save**

GitHub will automatically deploy your site to: `https://<username>.github.io/<repository>/`

### 3. Access Your Web App

After a few minutes, your site will be live at:
- `https://vdonga.github.io/vulnrichment/`

## Project Structure

```
docs/
├── index.html          # Main HTML page
├── styles.css          # Stylesheet with responsive design
├── app.js             # JavaScript for data loading and interactivity
├── cve-index.json     # Generated index file (not in git)
└── README.md          # This file
```

## How It Works

1. **Index Generation**: The Python script scans all CVE JSON files and extracts key information (CVE ID, severity, CVSS score, description, etc.) into a single index file.

2. **Data Loading**: The web app loads the index file and displays it in a paginated table.

3. **Client-Side Processing**: All filtering, searching, and sorting happens in the browser for fast, responsive interactions.

4. **Static Hosting**: Since everything is client-side, it can be hosted on GitHub Pages without any server infrastructure.

## Customization

### Modify the Data Display

Edit `app.js` to change which fields are extracted and displayed:

```javascript
// In the renderTable() function
row.innerHTML = `
    <td class="cve-id">${cve.cveId}</td>
    <td>...</td>
    // Add more columns here
`;
```

### Adjust Styling

Edit `styles.css` to customize colors, fonts, and layout:

```css
:root {
    --primary-color: #0066cc;  /* Change the primary color */
    --background: #f5f7fa;     /* Change background color */
}
```

### Change Page Size

Edit `app.js` to modify default pagination:

```javascript
let pageSize = 50;  // Change default items per page
```

## Performance Considerations

- **Full Index**: The complete index (~236k CVEs) will result in a ~150-200 MB JSON file
- **Limited Index**: For better performance, generate a limited index (e.g., recent CVEs only)
- **Lazy Loading**: Consider implementing lazy loading for very large datasets

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+
- Mobile browsers (iOS Safari, Chrome Mobile)

## Contributing

Found a bug or want to add a feature? Open an issue or pull request!

## License

This web viewer is part of the CISA Vulnrichment project. See the main repository LICENSE for details.
