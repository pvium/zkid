import { timingSafeEqual } from 'node:crypto';
import express, { type Request, type Response, type NextFunction } from 'express';
import { AttestationService } from './attestation.js';
import type { ProverConfig } from './config.js';
import { InputError } from './errors.js';
import { QueueFullError } from './prove.js';
import { parseCallbackUrl, runWebhookJob } from './webhook.js';
import { randomUUID } from 'node:crypto';

export function createApp(cfg: ProverConfig, secret: string) {
  if (!secret) throw new Error('AUTH_TOKEN is required');
  const service = new AttestationService(cfg);
  const app = express();
  app.locals.service = service; // for tests and graceful shutdown
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true, circuitVersion: service.version.circuitVersion, vkHash: service.version.vkSha256, ...service.stats });
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
    const body = req.body ?? {};
    if (service.stats.queued >= cfg.maxQueue && service.stats.inFlight >= cfg.maxConcurrency) {
      res.set('retry-after', '10').status(503).json({ error: 'prover busy; retry later', ...service.stats });
      return;
    }
    if (body.callbackUrl !== undefined) {
      const callback = parseCallbackUrl(body.callbackUrl, cfg.allowHttpCallbacks);
      const jobId = randomUUID();
      // Validate cheaply before accepting, so a malformed request still gets a 400 not a webhook error.
      service.validateRequest(body);
      void runWebhookJob(service, body, callback, jobId);
      res.status(202).json({ jobId, status: 'queued', ...service.stats });
      return;
    }
    res.json(await service.generate(body));
  });

  app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof InputError) {
      res.status(err.status).json({ error: err.message });
    } else if (err instanceof QueueFullError) {
      res.set('retry-after', '10').status(503).json({ error: err.message });
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
