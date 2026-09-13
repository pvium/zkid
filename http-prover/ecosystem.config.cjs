// PM2: `pm2 start ecosystem.config.cjs && pm2 save && pm2 startup`
// Secrets live in .env (read by --env-file), never here.
module.exports = {
  apps: [
    {
      name: 'pvium-prover',
      script: 'dist/server.js',
      node_args: '--env-file=.env',
      instances: 2, // noir_js solving blocks the event loop ~3 s; a second instance keeps /healthz answering
      exec_mode: 'cluster',
      max_memory_restart: '3500M',
    },
  ],
};
