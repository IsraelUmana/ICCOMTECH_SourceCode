const https = require('https');
const fs = require('fs');

// NVD API v2.0 - using https.get for better compatibility
function fetchNVDData(url) {
    return new Promise((resolve, reject) => {
        https.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (research-script)',
                'Accept': 'application/json'
            }
        }, (res) => {
            let data = '';
            
            console.log(`Status Code: ${res.statusCode}`);
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try {
                        const parsed = JSON.parse(data);
                        resolve(parsed);
                    } catch (e) {
                        reject(new Error(`JSON parse error: ${e.message}. Raw data: ${data.substring(0, 500)}`));
                    }
                } else if (res.statusCode === 403) {
                    reject(new Error('403 Forbidden - API may require authentication or rate limiting'));
                } else {
                    reject(new Error(`HTTP ${res.statusCode}: ${data.substring(0, 500)}`));
                }
            });
        }).on('error', (err) => {
            reject(new Error(`Request failed: ${err.message}`));
        });
    });
}

async function fetchJavaScriptCVEs() {
    const allCVEs = [];
    
    // Try multiple search queries (NVD API can be picky about keywords)
    const searchQueries = [
        {
            name: 'JavaScript injection',
            params: new URLSearchParams({
                keywordSearch: 'javascript injection',
                pubStartDate: '2020-01-01T00:00:00.000',
                pubEndDate: '2025-12-31T00:00:00.000',
                cvssV3Severity: 'HIGH,CRITICAL',
                resultsPerPage: '20'
            })
        },
        {
            name: 'cross site scripting javascript',
            params: new URLSearchParams({
                keywordSearch: 'cross site scripting javascript',
                pubStartDate: '2020-01-01T00:00:00.000',
                pubEndDate: '2025-12-31T00:00:00.000',
                cvssV3Severity: 'HIGH,CRITICAL',
                resultsPerPage: '20'
            })
        },
        {
            name: 'prototype pollution',
            params: new URLSearchParams({
                keywordSearch: 'prototype pollution',
                pubStartDate: '2020-01-01T00:00:00.000',
                pubEndDate: '2025-12-31T00:00:00.000',
                resultsPerPage: '20'
            })
        },
        {
            name: 'node.js vulnerability',
            params: new URLSearchParams({
                keywordSearch: 'node.js',
                pubStartDate: '2020-01-01T00:00:00.000',
                pubEndDate: '2025-12-31T00:00:00.000',
                cvssV3Severity: 'HIGH,CRITICAL',
                resultsPerPage: '20'
            })
        }
    ];

    const seenCVEIds = new Set();

    for (const query of searchQueries) {
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${query.params.toString()}`;
        console.log(`\n========================================`);
        console.log(`Searching: ${query.name}`);
        console.log(`========================================`);
        
        try {
            const data = await fetchNVDData(url);
            
            if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
                console.log(`  No results found for "${query.name}"`);
                console.log(`  Full response keys: ${Object.keys(data).join(', ')}`);
                if (data.totalResults !== undefined) {
                    console.log(`  Total results reported: ${data.totalResults}`);
                }
                continue;
            }

            console.log(`  Found ${data.vulnerabilities.length} CVEs`);
            
            for (const vuln of data.vulnerabilities) {
                const cveData = vuln.cve;
                
                // Skip duplicates
                if (seenCVEIds.has(cveData.id)) continue;
                seenCVEIds.add(cveData.id);
                
                const metrics = cveData.metrics?.cvssMetricV31?.[0]?.cvssData;
                const description = cveData.descriptions?.find(d => d.lang === 'en')?.value || '';
                
                allCVEs.push({
                    id: cveData.id,
                    description: description,
                    cvss_score: metrics?.baseScore || null,
                    severity: metrics?.baseSeverity || null,
                    published: cveData.published,
                    references: (cveData.references || []).slice(0, 5).map(r => r.url)
                });
            }
            
            // Be nice to the API - wait between requests
            await new Promise(resolve => setTimeout(resolve, 6000));
            
        } catch (error) {
            console.log(`  Error for "${query.name}": ${error.message}`);
        }
    }

    // Save results
    fs.writeFileSync('cve_candidates.json', JSON.stringify(allCVEs, null, 2));
    console.log(`\n========================================`);
    console.log(`TOTAL: Saved ${allCVEs.length} unique CVEs to cve_candidates.json`);
    console.log(`========================================\n`);
    
    // Print summary
    if (allCVEs.length === 0) {
        console.log('NO CVES FOUND. Try running again or using the manual list below.');
    } else {
        console.log('=== CVE IDs for Manual Review ===');
        allCVEs.forEach(cve => {
            const desc = cve.description.substring(0, 120).replace(/\n/g, ' ');
            console.log(`\n${cve.id} (CVSS ${cve.cvss_score})`);
            console.log(`  ${desc}...`);
        });
    }
}

fetchJavaScriptCVEs();