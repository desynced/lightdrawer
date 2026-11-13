import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['build/**', 'public/**', 'web/**', 'node_modules/**'] },
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
      // Parameters that exist for a caller or a platform signature, and are not
      // read in the body, keep a leading underscore.
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
];
