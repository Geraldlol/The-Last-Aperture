# V-008 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
#
# Bug class (exactly one): unsafe deserialization — request-controlled bytes reach
# a native object-graph deserializer.
# Lens: web-and-api / topic `deserialization-and-xxe`
# Expected: Critical, CWE-502
#
# `Marshal.load` reconstructs arbitrary Ruby objects and runs their hooks. It is
# on the owning lens's unconditional-sink list: unlike `YAML.load`, whose grade
# depends on the Psych major, and unlike `BinaryFormatter`, whose grade depends on
# the .NET target, this one needs no version to be read from a manifest. The bytes
# here come off a cookie the client sends, so the taint trace is one hop.
#
# The base64 decode in front of it is an encoding step, not a control. The
# `rescue` swallows the failure, which removes the only signal an operator would
# have had.
#
# NOT RUNNABLE and carries no payload: no Rack app is constructed, no middleware
# is inserted into a stack, nothing is required that exists in this repository,
# and there is no serialized object literal anywhere in the file. Building a
# gadget chain is deliberately left undone — the fixture is the sink, not the
# exploit.

require 'base64'

module Fixtures
  # Restores a "remember me" blob out of a cookie.
  class SessionRestore
    COOKIE_NAME = 'restore_state'

    def initialize(app)
      @app = app
    end

    # Rack-shaped middleware. `env` is the request; the cookie is the attacker's.
    def call(env)
      raw = cookies_from(env)[COOKIE_NAME]
      env['fixture.restored'] = restore(raw) if raw
      @app.call(env)
    end

    # The defect. Whatever the cookie decodes to is handed to Marshal, which
    # instantiates the classes named in the byte stream and invokes their
    # deserialization hooks before this method returns anything at all.
    def restore(raw)
      Marshal.load(Base64.decode64(raw))
    rescue StandardError
      # Swallowed, so a failed attempt looks exactly like a first-time visitor.
      nil
    end

    # For contrast, and to make the finding's remedy concrete: the same blob
    # round-trips through JSON with no object graph and no hooks. This method is
    # unused on the request path — it exists so a reader can see what the fix is
    # without a second file.
    def restore_as_data(raw)
      require 'json'
      JSON.parse(Base64.decode64(raw))
    rescue StandardError
      nil
    end

    private

    def cookies_from(env)
      header = env['HTTP_COOKIE'].to_s
      header.split('; ').each_with_object({}) do |pair, acc|
        name, _, value = pair.partition('=')
        acc[name] = value
      end
    end
  end
end
