import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import prettier from 'eslint-plugin-prettier/recommended';
import globals from 'globals';

export default tseslint.config(
  // Base ESLint recommended rules
  eslint.configs.recommended,

  // TypeScript recommended rules
  ...tseslint.configs.recommended,

  // Prettier integration (must be last to override formatting rules)
  prettier,

  // TypeScript source files
  {
    files: ['src/**/*.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        chrome: 'readonly',
      },
    },
    rules: {
      // TypeScript specific rules
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-non-null-assertion': 'warn',

      // General ESLint rules
      'no-console': 'off',
      'prefer-const': 'error',
      'no-var': 'error',
      eqeqeq: ['error', 'always'],
      curly: ['error', 'all'],
    },
  },

  // Test files
  {
    files: ['tests/**/*.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.jest,
        chrome: 'readonly',
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': 'off',
    },
  },

  // Ignored paths
  {
    ignores: [
      'node_modules/**',
      'dist/**',
      'build/**',
      'coverage/**',
      '*.js',
      '*.mjs',
    ],
  }
);
