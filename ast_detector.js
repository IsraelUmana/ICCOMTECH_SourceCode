const espree = require('espree');
const estraverse = require('estraverse');

class ASTDetector {
    constructor() {
        this.vulnerabilityPatterns = [
            // ===== CODE INJECTION RULES =====
            {
                id: 'AST-001',
                name: 'eval() call detected',
                class: 'code_injection',
                check: (node) => {
                    return node.type === 'CallExpression' &&
                           node.callee.type === 'Identifier' &&
                           node.callee.name === 'eval';
                },
                severity: 'high'
            },
            {
                id: 'AST-002',
                name: 'new Function() constructor',
                class: 'code_injection',
                check: (node) => {
                    return node.type === 'NewExpression' &&
                           node.callee.type === 'Identifier' &&
                           node.callee.name === 'Function';
                },
                severity: 'high'
            },
            {
                id: 'AST-003',
                name: 'setTimeout/setInterval with string argument',
                class: 'code_injection',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'Identifier' &&
                        ['setTimeout', 'setInterval'].includes(node.callee.name)) {
                        if (node.arguments.length > 0 &&
                            node.arguments[0].type === 'Literal' &&
                            typeof node.arguments[0].value === 'string') {
                            return true;
                        }
                    }
                    return false;
                },
                severity: 'medium'
            },
            {
                id: 'AST-004',
                name: 'Unsafe template literal in Function constructor',
                class: 'code_injection',
                check: (node) => {
                    if (node.type === 'NewExpression' &&
                        node.callee.type === 'Identifier' &&
                        node.callee.name === 'Function' &&
                        node.arguments.length > 0) {
                        const firstArg = node.arguments[0];
                        if (firstArg.type === 'TemplateLiteral' ||
                            (firstArg.type === 'BinaryExpression' && firstArg.operator === '+')) {
                            return true;
                        }
                    }
                    return false;
                },
                severity: 'high'
            },

            // ===== XSS RULES =====
            {
                id: 'AST-101',
                name: 'Assignment to innerHTML',
                class: 'xss',
                check: (node) => {
                    return node.type === 'AssignmentExpression' &&
                           node.left.type === 'MemberExpression' &&
                           node.left.property.type === 'Identifier' &&
                           node.left.property.name === 'innerHTML';
                },
                severity: 'high'
            },
            {
                id: 'AST-102',
                name: 'document.write() call',
                class: 'xss',
                check: (node) => {
                    return node.type === 'CallExpression' &&
                           node.callee.type === 'MemberExpression' &&
                           node.callee.object.type === 'Identifier' &&
                           node.callee.object.name === 'document' &&
                           node.callee.property.type === 'Identifier' &&
                           node.callee.property.name === 'write';
                },
                severity: 'high'
            },
            {
                id: 'AST-103',
                name: 'jQuery.html() with non-literal argument',
                class: 'xss',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'MemberExpression' &&
                        node.callee.property.type === 'Identifier' &&
                        node.callee.property.name === 'html' &&
                        node.arguments.length > 0) {
                        const arg = node.arguments[0];
                        if (arg.type !== 'Literal') return true;
                    }
                    return false;
                },
                severity: 'high'
            },
            {
                id: 'AST-104',
                name: 'Template literal in innerHTML assignment',
                class: 'xss',
                check: (node) => {
                    if (node.type === 'AssignmentExpression' &&
                        node.left.type === 'MemberExpression' &&
                        node.left.property.type === 'Identifier' &&
                        node.left.property.name === 'innerHTML' &&
                        node.right.type === 'TemplateLiteral' &&
                        node.right.expressions.length > 0) {
                        return true;
                    }
                    return false;
                },
                severity: 'high'
            },

            // ===== COMMAND INJECTION RULES =====
            {
                id: 'AST-201',
                name: 'exec() call with string concatenation or template',
                class: 'command_injection',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'Identifier' &&
                        node.callee.name === 'exec' &&
                        node.arguments.length > 0) {
                        const arg = node.arguments[0];
                        if (arg.type === 'BinaryExpression' ||
                            arg.type === 'TemplateLiteral') {
                            return true;
                        }
                    }
                    return false;
                },
                severity: 'critical'
            },
            {
                id: 'AST-202',
                name: 'spawn() with unsanitized arguments',
                class: 'command_injection',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'Identifier' &&
                        node.callee.name === 'spawn' &&
                        node.arguments.length >= 2) {
                        const argsArg = node.arguments[1];
                        if (argsArg.type === 'Identifier' ||
                            (argsArg.type === 'CallExpression' &&
                             argsArg.callee.type === 'MemberExpression' &&
                             argsArg.callee.property.type === 'Identifier' &&
                             argsArg.callee.property.name === 'split')) {
                            return true;
                        }
                    }
                    return false;
                },
                severity: 'high'
            },

            // ===== PROTOTYPE POLLUTION RULES =====
            {
                id: 'AST-301',
                name: 'for...in without hasOwnProperty check',
                class: 'prototype_pollution',
                check: (node) => {
                    if (node.type === 'ForInStatement') {
                        let hasOwnCheck = false;
                        estraverse.traverse(node.body, {
                            enter: (innerNode) => {
                                if (innerNode.type === 'CallExpression' &&
                                    innerNode.callee.type === 'MemberExpression' &&
                                    innerNode.callee.property.type === 'Identifier' &&
                                    innerNode.callee.property.name === 'hasOwnProperty') {
                                    hasOwnCheck = true;
                                }
                            }
                        });
                        return !hasOwnCheck;
                    }
                    return false;
                },
                severity: 'high'
            },
            {
                id: 'AST-302',
                name: 'Recursive merge function without prototype guard',
                class: 'prototype_pollution',
                check: (node) => {
                    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') {
                        const funcName = node.id?.name || '';
                        const nameLower = funcName.toLowerCase();
                        const isMerge = nameLower.includes('merge') || 
                                       nameLower.includes('extend') || 
                                       nameLower.includes('mixin') ||
                                       nameLower.includes('deep');
                        
                        if (isMerge && funcName.length > 0) {
                            let hasForIn = false;
                            let hasRecursiveCall = false;
                            let hasProtoGuard = false;
                            
                            estraverse.traverse(node.body, {
                                enter: (inner) => {
                                    if (inner.type === 'ForInStatement') hasForIn = true;
                                    if (inner.type === 'CallExpression' &&
                                        inner.callee.type === 'Identifier' &&
                                        inner.callee.name === funcName) {
                                        hasRecursiveCall = true;
                                    }
                                    if (inner.type === 'BinaryExpression' &&
                                        (inner.operator === '===' || inner.operator === '!==')) {
                                        if ((inner.left.type === 'Identifier' && 
                                             ['__proto__', 'constructor', 'prototype'].includes(inner.left.name)) ||
                                            (inner.right.type === 'Literal' && 
                                             ['__proto__', 'constructor', 'prototype'].includes(inner.right.value))) {
                                            hasProtoGuard = true;
                                        }
                                    }
                                }
                            });
                            
                            if (hasForIn && hasRecursiveCall && !hasProtoGuard) return true;
                        }
                    }
                    return false;
                },
                severity: 'high'
            },
            {
                id: 'AST-303',
                name: 'Object.assign with __proto__ key in arguments',
                class: 'prototype_pollution',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'MemberExpression' &&
                        node.callee.object.type === 'Identifier' &&
                        node.callee.object.name === 'Object' &&
                        node.callee.property.name === 'assign') {
                        for (const arg of node.arguments) {
                            if (arg.type === 'ObjectExpression') {
                                for (const prop of arg.properties) {
                                    if (prop.key.type === 'Identifier' && 
                                        (prop.key.name === '__proto__' || prop.key.name === 'constructor')) {
                                        return true;
                                    }
                                    if (prop.key.type === 'Literal' && 
                                        (prop.key.value === '__proto__' || prop.key.value === 'constructor')) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    return false;
                },
                severity: 'medium'
            },

            // ===== OPEN REDIRECT RULES =====
            {
                id: 'AST-401',
                name: 'window.location.href assignment with variable',
                class: 'open_redirect',
                check: (node) => {
                    if (node.type === 'AssignmentExpression' &&
                        node.left.type === 'MemberExpression' &&
                        node.left.property.type === 'Identifier' &&
                        node.left.property.name === 'href' &&
                        node.left.object.type === 'MemberExpression' &&
                        node.left.object.property.type === 'Identifier' &&
                        node.left.object.property.name === 'location') {
                        if (node.right.type !== 'Literal') return true;
                    }
                    return false;
                },
                severity: 'medium'
            },
            {
                id: 'AST-402',
                name: 'location.assign() or location.replace() with variable',
                class: 'open_redirect',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'MemberExpression' &&
                        node.callee.property.type === 'Identifier' &&
                        ['assign', 'replace'].includes(node.callee.property.name) &&
                        node.callee.object.type === 'MemberExpression' &&
                        node.callee.object.property.type === 'Identifier' &&
                        node.callee.object.property.name === 'location' &&
                        node.arguments.length > 0) {
                        if (node.arguments[0].type !== 'Literal') return true;
                    }
                    return false;
                },
                severity: 'medium'
            },
            {
                id: 'AST-403',
                name: 'res.redirect() with user input',
                class: 'open_redirect',
                check: (node) => {
                    if (node.type === 'CallExpression' &&
                        node.callee.type === 'MemberExpression' &&
                        node.callee.property.type === 'Identifier' &&
                        node.callee.property.name === 'redirect' &&
                        node.callee.object.type === 'Identifier' &&
                        node.callee.object.name === 'res' &&
                        node.arguments.length > 0) {
                        const arg = node.arguments[0];
                        if (arg.type === 'Identifier' || 
                            arg.type === 'MemberExpression') return true;
                    }
                    return false;
                },
                severity: 'medium'
            }
        ];
    }

    parseCode(codeString) {
        try {
            return espree.parse(codeString, {
                ecmaVersion: 2022,
                loc: true,
                range: true
            });
        } catch (e) {
            console.error(`Parse error: ${e.message}`);
            return null;
        }
    }

    detect(codeString) {
        const ast = this.parseCode(codeString);
        if (!ast) return [];

        const detected = [];
        
        estraverse.traverse(ast, {
            enter: (node) => {
                for (const pattern of this.vulnerabilityPatterns) {
                    try {
                        if (pattern.check(node)) {
                            const existing = detected.find(d => d.rule_id === pattern.id);
                            if (existing) {
                                existing.occurrences++;
                            } else {
                                detected.push({
                                    rule_id: pattern.id,
                                    name: pattern.name,
                                    class: pattern.class,
                                    severity: pattern.severity,
                                    occurrences: 1,
                                    location: node.loc
                                });
                            }
                        }
                    } catch (e) {
                        // Skip patterns that throw on unexpected node structures
                    }
                }
            }
        });

        return detected;
    }

    isVulnerable(codeString) {
        return this.detect(codeString).length > 0;
    }
}

module.exports = ASTDetector;