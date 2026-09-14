// PM2: `pm2 start ecosystem.config.cjs && pm2 save && pm2 startup`
// Secrets live in .env (read by --env-file), never here.
module.exports = {
  apps: [
    {
      name: 'pvium-prover',
      script: 'dist/server.js',
      node_args: '--env-file=.env',
      // One instance: solving runs in a worker thread, so the HTTP loop stays responsive, and the
      // memory gate (MAX_CONCURRENCY × ~3 GB) is global. More instances multiply that memory.
      instances: 1,
      exec_mode: 'fork',
      max_memory_restart: '3500M',
      kill_timeout: 20000, // let an in-flight prove (~8 s) finish on reload before SIGKILL
      merge_logs: true,
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
    },
  ],
};
