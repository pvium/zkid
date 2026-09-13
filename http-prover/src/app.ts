import { timingSafeEqual } from 'node:crypto';
import express, { type Request, type Response, type NextFunction } from 'express';
import { AttestationService } from './attestation.js';
import type { ProverConfig } from './config.js';
import { InputError } from './errors.js';

export function createApp(cfg: ProverConfig, secret: string) {
  if (!secret) throw new Error('AUTH_TOKEN is required');
  const service = new AttestationService(cfg);
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, circuitVersion: service.version.circuitVersion, vkHash: service.version.vkSha256 });
  });

  const auth = (req: Request, res: Response, next: NextFunction) => {
    const got = Buffer.from(req.headers.authorization ?? '');
    const want = Buffer.from(`Bearer ${secret}`);
    if (got.length !== want.length || !timingSafeEqual(got, want)) {
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  };

  app.post('/attestations', auth, async (req, res) => {
    // Never log req.body: the jwt is a bearer credential for the user's Privy session.
    const attestation = await service.generate(req.body);
    res.json(attestation);
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof InputError) {
      res.status(err.status).json({ error: err.message });
    } else if (err && typeof err === 'object' && 'type' in err && (err as { type: string }).type === 'entity.too.large') {
      res.status(413).json({ error: 'body too large' });
    } else if (err instanceof SyntaxError) {
      res.status(400).json({ error: 'invalid JSON' });
    } else {
      console.error('attestation failed:', (err as Error).message);
      res.status(500).json({ error: 'proof generation failed' });
    }
  });

  return app;
}
