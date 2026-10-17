import js from '@eslint/js';
import globals from 'globals';

// Cloudflare Workers runtime globals not covered by node globals
const workerGlobals = {
  KVNamespace: 'readonly',
  FetchEvent: 'readonly',
  ExecutionContext: 'readonly',
  ScheduledController: 'readonly',
  HTMLRewriter: 'readonly',
  caches: 'readonly',
};

export default [
  {
    ignores: ['node_modules/**', 'assets/**', 'coverage/**', '.wrangler/**', 'dist/**'],
  },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node, ...workerGlobals },
    },
    rules: {
      eqeqeq: 'error',
      'prefer-const': 'error',
      'no-var': 'error',
      'no-throw-literal': 'error',
      'no-implicit-coercion': 'error',
      'no-undef-init': 'error',
      'object-shorthand': 'error',
      'prefer-promise-reject-errors': 'error',
      'no-unused-private-class-members': 'error',
      'no-async-promise-executor': 'error',
    },
  },
  {
    files: ['test/**/*.js'],
    languageOptions: {
      globals: { ...globals.node },
    },
    rules: {
      // tests may over-assert on purpose
      'no-unused-vars': ['error', { args: 'none' }],
    },
  },
];
