import { defineConfig } from 'rolldown';
import typescript from '@rolldown/plugin-typescript';

export default defineConfig({
  input: './src/maboii.ts',
  plugins: [
    typescript({
      tsconfig: './tsconfig.json',
      compilerOptions: {
        declaration: false,
        declarationDir: undefined
      }
    })
  ],
  output: [
    {
      file: 'dist/maboii.js',
      format: 'esm',
      sourcemap: true
    },
    {
      file: 'dist/maboii.cjs',
      format: 'cjs',
      sourcemap: true,
      exports: 'named'
    }
  ]
});
