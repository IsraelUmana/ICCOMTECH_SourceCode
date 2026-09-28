class SequenceDetector {
    constructor() {
        this.rules = [
            // ===== CODE INJECTION =====
            {
                id: 'SEQ-001',
                name: 'Unsafe eval with concatenation',
                class: 'code_injection',
                pattern: /eval\s*\(\s*['"`].*\+.*\)|eval\s*\(\s*.*\+/g,
                severity: 'high'
            },
            {
                id: 'SEQ-002',
                name: 'new Function constructor',
                class: 'code_injection',
                pattern: /new\s+Function\s*\(/g,
                severity: 'high'
            },
            {
                id: 'SEQ-003',
                name: 'setTimeout/setInterval with string',
                class: 'code_injection',
                pattern: /set(Timeout|Interval)\s*\(\s*['"`]/g,
                severity: 'medium'
            },

            // ===== XSS =====
            {
                id: 'SEQ-101',
                name: 'Unsafe innerHTML assignment',
                class: 'xss',
                pattern: /\.innerHTML\s*=/g,
                severity: 'high'
            },
            {
                id: 'SEQ-102',
                name: 'document.write usage',
                class: 'xss',
                pattern: /document\.write\s*\(/g,
                severity: 'high'
            },
            {
                id: 'SEQ-103',
                name: 'jQuery .html() call',
                class: 'xss',
                pattern: /\$\([^)]+\)\.html\(/g,
                severity: 'high'
            },

            // ===== COMMAND INJECTION =====
            {
                id: 'SEQ-201',
                name: 'exec with concatenation or template',
                class: 'command_injection',
                pattern: /exec\s*\(\s*(?:.*\+|`[^`]*\$\{)/g,
                severity: 'critical'
            },
            {
                id: 'SEQ-202',
                name: 'spawn with variable arguments',
                class: 'command_injection',
                pattern: /spawn\s*\([^,]+,\s*(?!\[)/g,
                severity: 'high'
            },

            // ===== PROTOTYPE POLLUTION =====
            {
                id: 'SEQ-301',
                name: 'for...in without hasOwnProperty (entire block)',
                class: 'prototype_pollution',
                // Broad pattern: flag any for...in that doesn't contain hasOwnProperty
                // We check this in a custom post-processing step
                pattern: null,
                severity: 'high',
                customCheck: (code) => {
                    // Find all for...in blocks
                    const forInRegex = /for\s*\(\s*(?:var|let|const)?\s*(\w+)\s+in\s+(\w+)\s*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
                    let match;
                    let found = false;
                    while ((match = forInRegex.exec(code)) !== null) {
                        const blockContent = match[3];
                        if (!blockContent.includes('hasOwnProperty')) {
                            found = true;
                            break;
                        }
                    }
                    return found;
                }
            },
            {
                id: 'SEQ-302',
                name: 'merge/extend function pattern',
                class: 'prototype_pollution',
                pattern: /function\s*(?:merge|extend|mixin|deep|defaultsDeep|deepExtend)\s*\(/gi,
                severity: 'medium'
            },

            // ===== OPEN REDIRECT =====
            {
                id: 'SEQ-401',
                name: 'location.href assignment',
                class: 'open_redirect',
                pattern: /(?:window\.)?location\.href\s*=/g,
                severity: 'medium'
            },
            {
                id: 'SEQ-402',
                name: 'location.assign() or location.replace()',
                class: 'open_redirect',
                pattern: /(?:window\.)?location\.(?:assign|replace)\s*\(/g,
                severity: 'medium'
            },
            {
                id: 'SEQ-403',
                name: 'res.redirect() in Express',
                class: 'open_redirect',
                pattern: /res\.redirect\s*\(/g,
                severity: 'medium'
            }
        ];
    }

    detect(codeString) {
        const detected = [];
        for (const rule of this.rules) {
            if (rule.customCheck) {
                if (rule.customCheck(codeString)) {
                    detected.push({
                        rule_id: rule.id,
                        name: rule.name,
                        class: rule.class,
                        severity: rule.severity,
                        match_count: 1
                    });
                }
            } else if (rule.pattern) {
                const matches = codeString.match(rule.pattern);
                if (matches) {
                    detected.push({
                        rule_id: rule.id,
                        name: rule.name,
                        class: rule.class,
                        severity: rule.severity,
                        match_count: matches.length,
                        matches: matches
                    });
                }
            }
        }
        return detected;
    }

    isVulnerable(codeString) {
        return this.detect(codeString).length > 0;
    }
}

module.exports = SequenceDetector;