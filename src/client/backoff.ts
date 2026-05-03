const INITIAL_MS = 1_000;
const MAX_MS = 60_000;
const JITTER = 0.2;
const MULT = 2;

export interface Backoff {
  next: () => number;
  reset: () => void;
}

export function newBackoff(): Backoff {
  let cur = INITIAL_MS;
  return {
    next: () => {
      const v = cur;
      const jitter = 1 + (Math.random() * 2 - 1) * JITTER;
      cur = Math.min(cur * MULT, MAX_MS);
      return Math.round(Math.min(v * jitter, MAX_MS * (1 + JITTER)));
    },
    reset: () => {
      cur = INITIAL_MS;
    },
  };
}
