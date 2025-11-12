// Global state
let allComparisons = [];
let filteredComparisons = [];
let currentPage = 1;
let pageSize = 25;
let coverageFilter = 'all'; // 'all', 'cisa', 'nvd'
let metadata = null;
let loadedPages = new Set();

// Initialize the app
document.addEventListener('DOMContentLoaded', async () => {
    setupEventListeners();
    await loadComparisonData();
});

// Setup event listeners
function setupEventListeners() {
    // Search
    document.getElementById('searchInput').addEventListener('input', debounce(applyFilters, 300));
    
    // Filters
    document.getElementById('yearFilter').addEventListener('change', applyFilters);
    document.getElementById('severityFilter').addEventListener('change', applyFilters);
    
    // Coverage filter toggle
    document.querySelectorAll('.toggle-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            coverageFilter = e.target.dataset.filter;
            applyFilters();
        });
    });
    
    // Pagination
    document.getElementById('prevPage').addEventListener('click', () => changePage(-1));
    document.getElementById('nextPage').addEventListener('click', () => changePage(1));
}

// Load comparison data
async function loadComparisonData() {
    try {
        // Load metadata first
        updateLoadingProgress('Loading metadata...');
        const metaResponse = await fetch('comparison-metadata.json?v=2');
        if (!metaResponse.ok) throw new Error('Failed to load metadata');
        metadata = await metaResponse.json();
        
        console.log('Metadata loaded:', metadata);
        
        // Load first 5 pages
        const initialPages = Math.min(5, metadata.pages);
        for (let i = 1; i <= initialPages; i++) {
            updateLoadingProgress(`Loading initial data... (${i}/${initialPages} pages)`);
            await loadPage(i);
        }
        
        filteredComparisons = [...allComparisons];
        
        populateYearFilter();
        updateStats();
        renderTable();
        
        document.getElementById('loading').style.display = 'none';
        
        // Continue loading remaining pages in background
        loadRemainingPages();
    } catch (error) {
        console.error('Error loading data:', error);
        document.getElementById('loading').innerHTML = `
            <div class="spinner" style="border-top-color: #dc3545;"></div>
            <p class="loading-text" style="color: #dc3545;">Error loading comparison data: ${error.message}</p>
            <p style="color: #666; font-size: 0.9em;">Check browser console for details.</p>
        `;
    }
}

// Update loading progress message
function updateLoadingProgress(message) {
    const progressEl = document.getElementById('loadingProgress');
    if (progressEl) {
        progressEl.textContent = message;
    }
}

// Load a specific page of data
async function loadPage(pageNum) {
    if (loadedPages.has(pageNum)) return;
    
    try {
        const response = await fetch(`data/page_${pageNum}.json`);
        if (!response.ok) throw new Error(`Failed to load page ${pageNum}`);
        
        const pageData = await response.json();
        allComparisons = allComparisons.concat(pageData);
        loadedPages.add(pageNum);
        
        console.log(`Loaded page ${pageNum}: ${pageData.length} CVEs (Total: ${allComparisons.length}/${metadata.total})`);
    } catch (error) {
        console.error(`Error loading page ${pageNum}:`, error);
    }
}

// Load remaining pages in background
async function loadRemainingPages() {
    for (let page = 6; page <= metadata.pages; page++) {
        await loadPage(page);
        filteredComparisons = [...allComparisons];
        
        // Update display every 10 pages
        if (page % 10 === 0) {
            populateYearFilter();
            updateStats();
            applyFilters();
        }
    }
    populateYearFilter();
    updateStats();
    applyFilters();
    console.log('✅ All pages loaded!');
}

// Populate year filter based on actual data
function populateYearFilter() {
    const years = new Set();
    allComparisons.forEach(cve => {
        if (cve.year) years.add(cve.year);
    });
    
    const yearFilter = document.getElementById('yearFilter');
    const currentValue = yearFilter.value;
    
    // Keep "All Years" option and populate the rest
    const sortedYears = Array.from(years).sort((a, b) => b - a); // Descending order
    yearFilter.innerHTML = '<option value="">All Years</option>';
    sortedYears.forEach(year => {
        const option = document.createElement('option');
        option.value = year;
        option.textContent = year;
        yearFilter.appendChild(option);
    });
    
    // Restore previous selection if it still exists
    if (currentValue && sortedYears.includes(parseInt(currentValue))) {
        yearFilter.value = currentValue;
    }
}

// Apply filters
function applyFilters() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const yearFilter = document.getElementById('yearFilter').value;
    const severityFilter = document.getElementById('severityFilter').value;
    
    filteredComparisons = allComparisons.filter(cve => {
        // Search filter
        if (searchTerm) {
            const searchMatch = 
                cve.cveId.toLowerCase().includes(searchTerm) ||
                (cve.cisa.description && cve.cisa.description.toLowerCase().includes(searchTerm)) ||
                (cve.nvd.description && cve.nvd.description.toLowerCase().includes(searchTerm)) ||
                cve.vendors.some(v => v.toLowerCase().includes(searchTerm)) ||
                cve.products.some(p => p.toLowerCase().includes(searchTerm));
            
            if (!searchMatch) return false;
        }
        
        // Year filter
        if (yearFilter && cve.year != yearFilter) return false;
        
        // Severity filter (check both CISA and NVD)
        if (severityFilter) {
            const cisaMatch = cve.cisa.severity === severityFilter;
            const nvdMatch = cve.nvd.severity === severityFilter;
            if (!cisaMatch && !nvdMatch) return false;
        }
        
        // Coverage filter
        if (coverageFilter === 'cisa' && cve.analysis.betterCoverage !== 'cisa') return false;
        if (coverageFilter === 'nvd' && cve.analysis.betterCoverage !== 'nvd') return false;
        
        return true;
    });
    
    currentPage = 1;
    updateStats();
    renderTable();
}

// Update statistics based on filtered data
function updateStats() {
    const cisaScores = filteredComparisons.filter(c => c.cisa.score !== null).length;
    const nvdScores = filteredComparisons.filter(c => c.nvd.score !== null).length;
    const cisaProducts = filteredComparisons.filter(c => c.cisa.affectedCount > 0).length;
    const nvdProducts = filteredComparisons.filter(c => c.nvd.affectedCount > 0).length;
    
    let cisaWins = 0, nvdWins = 0;
    filteredComparisons.forEach(c => {
        if (c.analysis.betterCoverage === 'cisa') cisaWins++;
        else if (c.analysis.betterCoverage === 'nvd') nvdWins++;
    });
    
    // Update stat values
    document.getElementById('totalCount').textContent = filteredComparisons.length;
    document.getElementById('scoreCount').textContent = `${cisaScores}/${nvdScores}`;
    document.getElementById('productCount').textContent = `${cisaProducts}/${nvdProducts}`;
    document.getElementById('coverageWins').textContent = `${cisaWins}/${nvdWins}`;
}

// Render table
function renderTable() {
    const tbody = document.getElementById('tableBody');
    const start = (currentPage - 1) * pageSize;
    const end = start + pageSize;
    const pageData = filteredComparisons.slice(start, end);
    
    if (pageData.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No CVEs found</td></tr>';
        updatePagination();
        return;
    }
    
    tbody.innerHTML = pageData.map((cve, idx) => {
        const cisaScore = cve.cisa.score ? 
            `<span class="badge badge-score">${cve.cisa.score}</span>` : 
            '<span class="badge badge-none">None</span>';
        
        const nvdScore = cve.nvd.score ? 
            `<span class="badge badge-score">${cve.nvd.score}</span>` : 
            '<span class="badge badge-none">None</span>';
        
        let matchBadge = '<span class="badge badge-na">N/A</span>';
        if (cve.cisa.score && cve.nvd.score) {
            matchBadge = cve.analysis.scoreMatch ? 
                '<span class="badge badge-yes">✓</span>' : 
                '<span class="badge badge-no">✗</span>';
        }
        
        let coverageBadge = '<span class="badge badge-equal">Equal</span>';
        if (cve.analysis.betterCoverage === 'cisa') {
            coverageBadge = '<span class="badge badge-cisa">CISA</span>';
        } else if (cve.analysis.betterCoverage === 'nvd') {
            coverageBadge = '<span class="badge badge-nvd">NVD</span>';
        }
        
        // Build CISA products HTML
        const cisaProductsHtml = cve.cisa.affectedProducts.slice(0, 10).map(p => {
            const vendorProduct = `${p.vendor} / ${p.product}`;
            
            // Build version string
            let versionParts = [];
            const version = p.version;
            if (version && !['*', 'n/a', 'N/A'].includes(version) && !/[<>=]/.test(version)) {
                versionParts.push(`v${version}`);
            } else if (version && /[<>=]/.test(version)) {
                versionParts.push(version);
            }
            
            if (p.lessThan) versionParts.push(`< ${p.lessThan}`);
            if (p.lessThanOrEqual) versionParts.push(`≤ ${p.lessThanOrEqual}`);
            if (p.versionStartIncluding) versionParts.push(`≥ ${p.versionStartIncluding}`);
            if (p.versionEndIncluding) versionParts.push(`≤ ${p.versionEndIncluding}`);
            if (p.versionEndExcluding) versionParts.push(`< ${p.versionEndExcluding}`);
            
            const versionInfo = versionParts.length > 0 ? versionParts.join(' ') : 'All versions';
            
            return `<div class="product-item"><strong>${vendorProduct}</strong><br>${versionInfo}</div>`;
        }).join('');
        
        const cisaProductsDisplay = cisaProductsHtml || '<em>No affected products data</em>';
        const cisaMoreText = cve.cisa.affectedCount > 10 ? `<div class="product-item"><em>... and ${cve.cisa.affectedCount - 10} more</em></div>` : '';
        
        // Build NVD products HTML
        const nvdProductsHtml = cve.nvd.affectedProducts.slice(0, 10).map(p => {
            const vendorProduct = `${p.vendor} / ${p.product}`;
            
            // Build version string
            let versionParts = [];
            const version = p.version;
            if (version && !['*', 'n/a', 'N/A'].includes(version) && !/[<>=]/.test(version)) {
                versionParts.push(`v${version}`);
            } else if (version && /[<>=]/.test(version)) {
                versionParts.push(version);
            }
            
            if (p.versionStartIncluding) versionParts.push(`≥ ${p.versionStartIncluding}`);
            if (p.versionStartExcluding) versionParts.push(`> ${p.versionStartExcluding}`);
            if (p.versionEndIncluding) versionParts.push(`≤ ${p.versionEndIncluding}`);
            if (p.versionEndExcluding) versionParts.push(`< ${p.versionEndExcluding}`);
            
            const versionInfo = versionParts.length > 0 ? versionParts.join(' ') : 'All versions';
            
            return `<div class="product-item"><strong>${vendorProduct}</strong><br>${versionInfo}</div>`;
        }).join('');
        
        const nvdProductsDisplay = nvdProductsHtml || '<em>No CPE data</em>';
        const nvdMoreText = cve.nvd.affectedCount > 10 ? `<div class="product-item"><em>... and ${cve.nvd.affectedCount - 10} more</em></div>` : '';
        
        return `
            <tr onclick="toggleDetails(${idx})" style="cursor: pointer;">
                <td class="cve-id"><a href="https://nvd.nist.gov/vuln/detail/${cve.cveId}" target="_blank" onclick="event.stopPropagation()">${cve.cveId}</a></td>
                <td>${cve.year || 'N/A'}</td>
                <td>${cisaScore}</td>
                <td>${nvdScore}</td>
                <td>${matchBadge}</td>
                <td>${cve.cisa.affectedCount}</td>
                <td>${cve.nvd.affectedCount}</td>
                <td>${coverageBadge}</td>
            </tr>
            <tr class="expanded-row">
                <td colspan="8">
                    <div class="expanded-content" id="details-${idx}">
                        <div class="data-section">
                            <h4>Descriptions</h4>
                            <div class="side-by-side">
                                <div class="source-data">
                                    <h5>CISA Description</h5>
                                    <p>${cve.cisa.description || 'No description available'}</p>
                                </div>
                                <div class="source-data">
                                    <h5>NVD Description</h5>
                                    <p>${cve.nvd.description || 'No description available'}</p>
                                </div>
                            </div>
                        </div>
                        
                        <div class="data-section">
                            <h4>Affected Products</h4>
                            <div class="side-by-side">
                                <div class="source-data">
                                    <h5>CISA Products (${cve.cisa.affectedCount})
                                        <a class="json-icon" onclick="showJsonModal(event, ${idx})" title="View raw JSON">[JSON]</a>
                                    </h5>
                                    <div class="product-list">
                                        ${cisaProductsDisplay}
                                        ${cisaMoreText}
                                    </div>
                                </div>
                                <div class="source-data">
                                    <h5>NVD Products (${cve.nvd.affectedCount})
                                        <a class="json-icon" onclick="showCpeModal(event, ${idx})" title="View raw CPE strings">[CPE]</a>
                                    </h5>
                                    <div class="product-list">
                                        ${nvdProductsDisplay}
                                        ${nvdMoreText}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
        `;
    }).join('');
    
    updatePagination();
}

// Update pagination controls
function updatePagination() {
    const totalPages = Math.ceil(filteredComparisons.length / pageSize);
    
    document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages || 1}`;
    document.getElementById('prevPage').disabled = currentPage === 1;
    document.getElementById('nextPage').disabled = currentPage >= totalPages;
}

// Change page
function changePage(delta) {
    const totalPages = Math.ceil(filteredComparisons.length / pageSize);
    const newPage = currentPage + delta;
    
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        renderTable();
        window.scrollTo(0, 0);
    }
}

// Toggle expandable row details
function toggleDetails(idx) {
    const details = document.getElementById(`details-${idx}`);
    details.classList.toggle('active');
}

// Show JSON modal
function showJsonModal(event, idx) {
    event.stopPropagation();
    
    const start = (currentPage - 1) * pageSize;
    const cve = filteredComparisons[start + idx];
    
    if (!cve) return;
    
    document.getElementById('modalTitle').textContent = 'CISA Raw Affected Products (JSON)';
    const jsonContent = JSON.stringify(cve.cisa.rawAffected, null, 2);
    document.getElementById('jsonContent').textContent = jsonContent;
    document.getElementById('jsonModal').style.display = 'block';
}

// Show CPE modal
function showCpeModal(event, idx) {
    event.stopPropagation();
    
    const start = (currentPage - 1) * pageSize;
    const cve = filteredComparisons[start + idx];
    
    if (!cve || !cve.nvd.rawCPEs) return;
    
    document.getElementById('modalTitle').textContent = 'NVD Raw CPE Strings';
    const cpeContent = cve.nvd.rawCPEs.join('\n\n');
    document.getElementById('jsonContent').textContent = cpeContent;
    document.getElementById('jsonModal').style.display = 'block';
}

// Close JSON modal
function closeJsonModal() {
    document.getElementById('jsonModal').style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('jsonModal');
    if (event.target == modal) {
        modal.style.display = 'none';
    }
}

// Debounce helper
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
