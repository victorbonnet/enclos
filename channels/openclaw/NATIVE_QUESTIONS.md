# Native question boundary

Tested source: the installed public OpenClaw **2026.11.2** package. This channel
preserves native question text and trusted Control UI flows. It does not advertise
the enclos `questions` capability or accept `question.answer`/`question.sync`.
Unsupported controls remain explicit `unsupported` errors.

## Implemented delivery

The public `openclaw/plugin-sdk/interactive-runtime` helper
`renderPresentationForDelivery({}, payload)` produces the complete native text
fallback before an inbound dispatcher reply is queued. It retains every text,
context, option, table and chart supported by native rendering; it does not select
the first question from a batch. An existing `presentationTextMode: "fallback"`
text remains authoritative, avoiding a second copy of the prompt. Native outbound
delivery already applies this same rendering policy before `sendText`.

`sendQuestionToolPrompt` in native `src/agents/tools/question-prompt-send.ts`
keeps credential requests out of ordinary chat: it sends a trusted Control UI
link, or a message explaining that the trusted UI is unavailable and that
credentials must never be sent in chat. The channel passes that text through and
adds no credential-answer path. Native `ask_user` supports one to three questions,
including multiple selections; those prompts retain their complete native text.

The installed-SDK test executes the actual public fallback renderer against a
two-question presentation with buttons, context and a selection list. It also
checks existing fallback text and credential guidance. Transport tests establish
that no question capability is advertised and account authority is checked again
after asynchronous rendering. These are source and fixture checks; they do not
claim a live model question/answer round trip.

## Why richer cards remain a follow-up

The public `openclaw/plugin-sdk/question-gateway-runtime` contract is narrower
than the current enclos structured question contract:

| Native surface | Supported behavior | Missing for faithful enclos cards |
| --- | --- | --- |
| `resolveOption` | Reads the exact native record, then resolves one ordinary, single-selection question by option value/index; rechecks an optional authorizer immediately before writing | No public read/list or safe reconnect reconciliation; no Skip operation; custom-input is only a transition, not a submitted answer |
| `prepareReactionPayloadForDelivery` | Converts one button block with one to four choices into reaction hints | Does not prove a canonical single ordinary question; takes only the first text block and cannot be the decoder for batches/forms/secrets |
| `registerChannelDelivery` | Notifies native expiry/cancellation/settlement through a display `statusLine` | No typed authoritative answer receipt; a line such as `Answered` cannot establish which phone action was accepted |

The resolver uses `bindAgentToolGatewayRequest({ hostedOnly: true })` with
`operator.questions` and can fall back to the normal Gateway transport when no
owned hosted caller is admitted. An enclos Unix socket callback must not obtain
that authority by inventing a request scope or borrowing broad Gateway
credentials. The public general `dispatchGatewayMethod` is explicitly scoped to
authenticated plugin HTTP/RPC handlers. In contrast, the native account lifecycle
provides an explicit `approval.native` context restricted to `approval.resolve`;
that approval principal does not authorize question methods.

A future card implementation therefore needs an established native channel
question capability, or an explicitly authenticated public handler with exact
account/person/session authority. It also needs native read/reconciliation,
offered-control negotiation (without invented Other/Skip), and typed terminal
receipts or a neutral externally-resolved state. Native batches, multiple
selections, forms and secret requests must retain their native flow until each
shape can be represented faithfully. Parsing display status text or copying a
native question store does not provide that contract.

## Source locations inspected

Public entry points and declarations are shipped in `dist/plugin-sdk/`:
`interactive-runtime`, `question-gateway-runtime`, `gateway-method-runtime`.
The corresponding source-labelled sections in the installed distribution are:

- `src/channels/plugins/outbound/presentation-delivery.ts`
- `src/interactive/payload.ts` (native text fallback)
- `src/agents/tools/question-prompt-send.ts`
- `src/agents/tools/ask-user-tool-normalization.ts`
- `src/infra/question-gateway-resolver.ts`
- `src/infra/question-reaction-runtime.ts`
- `src/infra/question-channel-runtime.ts`
- `src/agents/tools/in-process-gateway.ts`
- `src/gateway/server-channels.ts`

These paths identify the native source sections, not files copied into enclos.
