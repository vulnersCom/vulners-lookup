import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'jsdom',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: 'tsconfig.test.json',
      useESM: false
    }]
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 20,
      functions: 15,
      lines: 18,
      statements: 18
    }
  },
  // Modern Jest options for better performance and output
  verbose: false,
  silent: false,
  clearMocks: true,
  restoreMocks: true,
  resetMocks: true,
  // Better error reporting
  errorOnDeprecated: true,
  // Performance improvements
  maxWorkers: '50%',
  // Test timeout (30 seconds for retry tests)
  testTimeout: 30000
};

export default config;