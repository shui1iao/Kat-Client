import { build } from 'vite';
await build({ configFile:false, root:process.cwd(), base:'./', cacheDir:'.vite-cache', logLevel:'warn', build:{outDir:'dist',emptyOutDir:true,modulePreload:false,cssCodeSplit:false} });
