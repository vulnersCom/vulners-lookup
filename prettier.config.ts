import type { Config } from 'prettier';

const config: Config = {
  semi: true,
  trailingComma: 'es5',
  singleQuote: true,
  printWidth: 80,
  tabWidth: 2,
  useTabs: false,
  bracketSpacing: true,
  bracketSameLine: false,
  arrowParens: 'always',
  endOfLine: 'lf',
  quoteProps: 'as-needed',
  jsxSingleQuote: true,
  overrides: [
    {
      files: ['*.ts', '*.tsx'],
      options: {
        parser: 'typescript',
      },
    },
    {
      files: '*.css',
      options: {
        singleQuote: false,
      },
    },
  ],
};

export default config;
