# Reference remote gateway

This directory contains the in-process conformance implementation for
`remote-gateway-v1`. It is not a hosted service and contains no upstream model
credential.

The reference acceptor demonstrates the protocol boundary:

1. require canonical JSON and an RFC 9530 `Content-Digest`;
2. verify the externally trusted controller Ed25519 key;
3. verify the request signature, time window, packet, prompt-transform, and
   exact sealed artifact bytes;
4. consume the one-use request ID before calling the provider;
5. bind the returned job result and upstream request digest; and
6. sign a `REMOTE_REQUEST_ACCEPTED` response with the gateway key.

The provider callback receives the verified portable packet and decoded exact
artifacts. It returns:

```js
{
  jobResult,
  upstreamRequestBytes
}
```

`upstreamRequestBytes` are the exact credential-free request body submitted by
the gateway to its model provider. The credential is never part of this value.

The replay store is a trust dependency. The default `Set` is suitable only for
single-process tests. A production gateway must consume request IDs durably
before the upstream call and return a cached terminal outcome or an explicit
duplicate response. It must never make an ambiguous failed request reusable.

See [ADR 0007](../../docs/adr/0007-signed-remote-request-acceptance.md) for the
trust model and residual risks.
