import { createRequire } from 'node:module';
const { Parser, Language } = await import('web-tree-sitter');
const req = createRequire(import.meta.url);
await Parser.init({ locateFile: () => req.resolve('web-tree-sitter/web-tree-sitter.wasm') });
const parser = new Parser();
const bash = await Language.load(req.resolve('tree-sitter-bash/tree-sitter-bash.wasm'));
parser.setLanguage(bash);

function printTree(n, depth) {
  console.log('  '.repeat(depth) + n.type + ' (' + n.childCount + ' kids) [' + n.text.slice(0,120).replace(/\n/g,'\\n') + ']');
  for (let i = 0; i < n.childCount; i++) {
    const c = n.child(i);
    if (c) printTree(c, depth+1);
  }
}

// Test $(...) inside double quotes
const tree = parser.parse('echo "$(basename file)"');
console.log('=== $() in double quotes ===');
printTree(tree.rootNode, 0);

// Test backticks
const tree2 = parser.parse('echo "`basename file`"');
console.log('\n=== backticks in double quotes ===');
printTree(tree2.rootNode, 0);

// Test backticks without quotes
const tree3 = parser.parse('echo `basename file`');
console.log('\n=== backticks without quotes ===');
printTree(tree3.rootNode, 0);

// Test process substitution
const tree4 = parser.parse('cat <(echo hi)');
console.log('\n=== process substitution ===');
printTree(tree4.rootNode, 0);

// Test nested subshell
const tree5 = parser.parse('cat $(echo $(basename file))');
console.log('\n=== nested $() ===');
printTree(tree5.rootNode, 0);
