const fs = require('fs');
const SequenceDetector = require('./sequence_detector');
const ASTDetector = require('./ast_detector');

// Load dataset
const dataset = JSON.parse(fs.readFileSync('dataset.json', 'utf8'));

// Initialize detectors
const seqDetector = new SequenceDetector();
const astDetector = new ASTDetector();

// Results structure
const results = {
    summary: {},
    by_class: {},
    detailed: []
};

// Track confusion matrix values
let TP_seq = 0, FP_seq = 0, TN_seq = 0, FN_seq = 0;
let TP_ast = 0, FP_ast = 0, TN_ast = 0, FN_ast = 0;

// Test each sample
for (const sample of dataset.samples) {
    const seqResultVuln = seqDetector.isVulnerable(sample.vulnerable_code);
    const seqResultSecure = seqDetector.isVulnerable(sample.secure_code);
    const astResultVuln = astDetector.isVulnerable(sample.vulnerable_code);
    const astResultSecure = astDetector.isVulnerable(sample.secure_code);

    // Sequence detector confusion matrix
    if (seqResultVuln) TP_seq++; else FN_seq++;
    if (seqResultSecure) FP_seq++; else TN_seq++;

    // AST detector confusion matrix
    if (astResultVuln) TP_ast++; else FN_ast++;
    if (astResultSecure) FP_ast++; else TN_ast++;

    // Store detailed results
    results.detailed.push({
        sample_id: sample.id,
        vulnerability_class: sample.vulnerability_class,
        cve_ref: sample.cve_ref,
        sequence: {
            vulnerable_detected: seqResultVuln,
            secure_detected: seqResultSecure
        },
        ast: {
            vulnerable_detected: astResultVuln,
            secure_detected: astResultSecure
        }
    });
}

// Calculate metrics
function calculateMetrics(TP, FP, TN, FN) {
    const precision = TP / (TP + FP) || 0;
    const recall = TP / (TP + FN) || 0;
    const f1 = 2 * (precision * recall) / (precision + recall) || 0;
    const accuracy = (TP + TN) / (TP + FP + TN + FN) || 0;
    return { precision, recall, f1, accuracy };
}

results.summary = {
    sequence: {
        confusion_matrix: { TP: TP_seq, FP: FP_seq, TN: TN_seq, FN: FN_seq },
        metrics: calculateMetrics(TP_seq, FP_seq, TN_seq, FN_seq)
    },
    ast: {
        confusion_matrix: { TP: TP_ast, FP: FP_ast, TN: TN_ast, FN: FN_ast },
        metrics: calculateMetrics(TP_ast, FP_ast, TN_ast, FN_ast)
    }
};

// Per-class breakdown
const classes = [...new Set(dataset.samples.map(s => s.vulnerability_class))];
for (const vc of classes) {
    const classSamples = dataset.samples.filter(s => s.vulnerability_class === vc);
    let cTP_seq = 0, cFP_seq = 0, cTN_seq = 0, cFN_seq = 0;
    let cTP_ast = 0, cFP_ast = 0, cTN_ast = 0, cFN_ast = 0;

    for (const sample of classSamples) {
        const sv = seqDetector.isVulnerable(sample.vulnerable_code);
        const ss = seqDetector.isVulnerable(sample.secure_code);
        const av = astDetector.isVulnerable(sample.vulnerable_code);
        const as = astDetector.isVulnerable(sample.secure_code);

        if (sv) cTP_seq++; else cFN_seq++;
        if (ss) cFP_seq++; else cTN_seq++;
        if (av) cTP_ast++; else cFN_ast++;
        if (as) cFP_ast++; else cTN_ast++;
    }

    results.by_class[vc] = {
        sample_count: classSamples.length,
        sequence: calculateMetrics(cTP_seq, cFP_seq, cTN_seq, cFN_seq),
        ast: calculateMetrics(cTP_ast, cFP_ast, cTN_ast, cFN_ast)
    };
}

// Save results
fs.writeFileSync('experiment_results.json', JSON.stringify(results, null, 2));
console.log('Experiment complete. Results saved to experiment_results.json');

// Print summary table
console.log('\n=== OVERALL RESULTS ===');
console.table({
    'Sequence-Based': results.summary.sequence.metrics,
    'AST-Based': results.summary.ast.metrics
});

console.log('\n=== PER-CLASS F1 SCORES ===');
const classTable = {};
for (const [cls, data] of Object.entries(results.by_class)) {
    classTable[cls] = {
        'Seq F1': data.sequence.f1.toFixed(3),
        'AST F1': data.ast.f1.toFixed(3),
        'Samples': data.sample_count
    };
}
console.table(classTable);