import { configDefaults, defineConfig } from 'vitest/config';
import { loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  return {
  plugins: [react(), {
    name: 'frp-admin-vendor-chunks',
    configEnvironment(name, config) {
      if (name !== 'client' || !config.build) return;
      config.build.rollupOptions ??= {};
      config.build.rollupOptions.output = {
        manualChunks(id) {
          if (id.includes('/react/') || id.includes('/react-dom/') || id.includes('/scheduler/')) return 'vendor-react';
          if (id.includes('/react-router') || id.includes('/@remix-run/')) return 'vendor-router';
          if (id.includes('/@tanstack/')) return 'vendor-query';
          if (id.includes('/dayjs/')) return 'vendor-dayjs';
          return undefined;
        },
      };
    },
  }],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': env.FRP_ADMIN_WEB_API_PROXY || 'http://127.0.0.1:8080',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    css: true,
    exclude: [...configDefaults.exclude, 'e2e/**'],
  },
  };
});
