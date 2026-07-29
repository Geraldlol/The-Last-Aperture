// C-006 / C-030 support file — clean fixture. Expected findings at Low or above: ZERO.
//
// This file exists so a reader can CHECK, rather than assume, the precondition
// mobile-app-security's false positive 1 depends on: that the shipped bundle is
// built with `dev: false`.
//
// What is deliberately absent, and why each absence matters:
//   * no `transformerPath` and no `transformer.babelTransformerPath` — a custom
//     transformer could re-inline `__DEV__` as true;
//   * no custom `serializer.customSerializer` — a serializer can rewrite the
//     module map after the transform has run;
//   * no `minifierEnabled` key, because that is NOT a Metro option: it is absent
//     from metro-config's defaults and silently dropped by Metro's known-key
//     schema, so its presence or absence proves nothing and citing it would build
//     the clearance on a dead literal.
//
// The `dev` flag itself is not set here and should not be: it is a bundle-command
// argument, not a config key, and the stock Gradle/Xcode release path passes
// `--dev false`. What this file guarantees is that nothing in the transform
// pipeline overrides it.

const { getDefaultConfig, mergeConfig } = require("@react-native/metro-config");

/** @type {import('metro-config').MetroConfig} */
const config = {
  resolver: {
    sourceExts: ["ts", "tsx", "js", "jsx", "json"],
  },
  transformer: {
    // Inline requires only. No transformer or babel-transformer override.
    getTransformOptions: async () => ({
      transform: {
        experimentalImportSupport: false,
        inlineRequires: true,
      },
    }),
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
