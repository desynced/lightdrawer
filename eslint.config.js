import js from '@eslint/js';
import globals from 'globals';

// Shared rule: parameters and caught errors that exist for a caller, a platform
// signature, or a try/catch that only needs to swallow the error keep a leading
// underscore when they are not read.
const unusedVars = ['error', { argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }];

export default [
  {
    ignores: [
      'build/*', 'build/*/**', '!build/verify.js',
      'public/*', 'public/*/**', '!public/app.js',
      // web/lib and the maker/verifier UI are plain scripts that share one scope
      // once concatenated, so they are linted as the built bundles below.
      'web/lib/**', 'web/ui/maker.js', 'web/ui/verify-ui.js',
      'node_modules/**',
    ],
  },
  js.configs.recommended,
  {
    files: ['src/**/*.js', 'scripts/**/*.mjs', 'test/**/*.js', 'test/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.browser,
      },
    },
    rules: {
      'no-unused-vars': unusedVars,
    },
  },
  {
    // Shipped browser code. public/app.js is the receipt maker (web/lib + stamp
    // link + web/ui/maker.js). build/verify.js is the exact script inlined into
    // public/verify.html (web/lib + web/ui/verify-ui.js). Both are classic scripts.
    files: ['public/app.js', 'build/verify.js', 'web/ui/button.js', 'web/snippets/lightdrawer-stamp.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'script',
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      'no-unused-vars': unusedVars,
    },
  },
];
