const fs = require('fs');
const espree = require('espree');

const dataset = JSON.parse(fs.readFileSync('dataset.json', 'utf8'));

console.log('=== CHECKING ALL SAMPLES FOR PARSE ERRORS ===\n');

let errorCount = 0;

for (const sample of dataset.samples) {
    // Check vulnerable code
    try {
        espree.parse(sample.vulnerable_code, { ecmaVersion: 2022 });
    } catch (e) {
        errorCount++;
        console.log(`❌ PARSE ERROR in ${sample.id} (VULNERABLE)`);
        console.log(`   CVE: ${sample.cve_ref}`);
        console.log(`   Class: ${sample.vulnerability_class}`);
        console.log(`   Error: ${e.message}`);
        console.log(`   Code:\n${sample.vulnerable_code.substring(0, 200)}...\n`);
    }
    
    // Check secure code
    try {
        espree.parse(sample.secure_code, { ecmaVersion: 2022 });
    } catch (e) {
        errorCount++;
        console.log(`❌ PARSE ERROR in ${sample.id} (SECURE)`);
        console.log(`   CVE: ${sample.cve_ref}`);
        console.log(`   Class: ${sample.vulnerability_class}`);
        console.log(`   Error: ${e.message}`);
        console.log(`   Code:\n${sample.secure_code.substring(0, 200)}...\n`);
    }
}

console.log(`\n=== TOTAL PARSE ERRORS: ${errorCount} ===`);