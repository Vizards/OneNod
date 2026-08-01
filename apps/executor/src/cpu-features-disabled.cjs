// ssh2 treats cpu-features as optional. Workers cannot load its native addon,
// so Wrangler aliases that package to this intentional "not available" result.
module.exports = function unavailableCpuFeatures() {
  return undefined;
};
