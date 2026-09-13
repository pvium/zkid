/** A request that can never succeed: bad token, unlinked identity, wrong signer, … (HTTP 400/401). */
export class InputError extends Error {
  constructor(message: string, public readonly status: 400 | 401 = 400) {
    super(message);
    this.name = 'InputError';
  }
}
