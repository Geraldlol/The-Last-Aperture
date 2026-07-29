// C-006 / C-030 support file — clean fixture. Expected findings at Low or above: ZERO.
//
// mobile-app-security's false positive 1 explicitly refuses to extend the `__DEV__`
// clearance to `console.log`: console calls are stripped only when the build
// configures it, and absent `transform-remove-console` or a `drop_console` minifier
// option they ship. So this fixture configures it rather than asking a reader to
// assume it.
//
// The plugin is in the `production` env block, which is the env Metro uses for a
// release bundle (`NODE_ENV=production`). Any `console.*` call that survives the
// `dev: false` dead-branch elimination is removed here as a second layer.

module.exports = function babel(api) {
  api.cache(true);

  return {
    presets: ["module:@react-native/babel-preset"],
    env: {
      production: {
        plugins: [
          // Removes console.* from the release bundle.
          "transform-remove-console",
        ],
      },
    },
  };
};
