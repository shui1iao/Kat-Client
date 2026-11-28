interface EpochGuard {
  capture: () => number;
  bump: () => number;
  isCurrent: (token: number) => boolean;
}

export function createEpochGuard(): EpochGuard {
  let epoch = 0;
  return {
    capture: () => epoch,
    bump: () => ++epoch,
    isCurrent: (token: number) => token === epoch,
  };
}
