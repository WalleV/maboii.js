import { defineConfig } from 'rolldown';

export default defineConfig([
  {
    input: './src/maboii.ts',
    output: {
      file: 'dist/maboii.js',
      format: 'esm',
      sourcemap: true
    }
  },
  {
    input: './src/maboii.ts',
    output: {
      dir: 'dist',
      format: 'cjs',
      sourcemap: true,
      exports: 'named',
      entryFileNames: '[name].cjs'
    }
  }
]);
