import * as esbuild from 'esbuild';
import type { BuildOptions } from 'esbuild';

const isWatch = process.argv.includes('--watch');
const isMinify = process.argv.includes('--minify');

// Common build options
const commonOptions: BuildOptions = {
  bundle: true,
  sourcemap: !isMinify, // No sourcemaps in production
  minify: isMinify,
  target: 'es2020',
  format: 'esm',
  logLevel: 'info',
};

// Build configurations for different entry points
const configs: BuildOptions[] = [
  {
    entryPoints: ['src/background.ts'],
    outfile: 'dist/background.js',
    ...commonOptions,
  },
  {
    entryPoints: ['src/content.ts'],
    outfile: 'dist/content.js',
    bundle: true,
    sourcemap: !isMinify,
    minify: isMinify,
    target: 'es2020',
    format: 'iife', // IIFE for content scripts (no ES module support in content script context)
    logLevel: 'info',
  },
  {
    entryPoints: ['src/popup.ts'],
    outfile: 'dist/popup.js',
    ...commonOptions,
  },
  {
    entryPoints: ['src/history-hook.ts'],
    outfile: 'dist/history-hook.js',
    bundle: true,
    sourcemap: !isMinify,
    minify: isMinify,
    target: 'es2020',
    format: 'iife', // IIFE for injected scripts
    logLevel: 'info',
  },
];

async function build() {
  try {
    if (isWatch) {
      // Watch mode - create contexts and watch
      const contexts = await Promise.all(
        configs.map((config) => esbuild.context(config))
      );
      await Promise.all(contexts.map((ctx) => ctx.watch()));
      console.log('Watching for changes...');
    } else {
      // One-time build
      await Promise.all(configs.map((config) => esbuild.build(config)));
      console.log('Build complete!');
    }
  } catch (error) {
    console.error('Build failed:', error);
    process.exit(1);
  }
}

build();
