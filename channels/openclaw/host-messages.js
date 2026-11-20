// The host's person's signed messages (ADR 0077, proposed). OpenClaw keeps
// some tools for its owner, named in `commands.ownerAllowFrom` as
// `enclos:host`, which `enclos runtime configure --channel app` writes. A
// message the bridge signed as the host's person's, in a direct conversation,
// reaches OpenClaw from that sender; every other one keeps its person, and
// none that is unsigned may take it. Match enclos_protocol::decision::HostMessage.
import { checkSigned, decisionKey } from './native-approvals.js';

export const OWNER_SENDER = 'host';
const LABEL = 'enclos/host-message/1';

// OpenClaw compares senders after trimming them, some channels ignore case,
// and an owner entry names the channel too: none of these may be unsigned.
const reserved = new Set([OWNER_SENDER, `enclos:${OWNER_SENDER}`]);
const isOwnerSender = person => typeof person === 'string' && reserved.has(person.trim().toLowerCase());

// The sender OpenClaw sees for `incoming`, given the bridge's public key (as
// configured) and the agent (`sandbox/agent`): { id, owner, refused? }.
export function hostSender(bridgeKey, agent, incoming, now = Math.floor(Date.now() / 1000)) {
  const reserved = isOwnerSender(incoming.person);
  if (incoming.signed == null) {
    return reserved ? { id: incoming.person, owner: false, refused: `an unsigned message cannot come from ${OWNER_SENDER}` }
      : { id: incoming.person, owner: false };
  }
  const failure = signatureFailure(bridgeKey, agent, incoming, now);
  if (failure) return { id: incoming.person, owner: false, refused: reserved ? failure : undefined, failure };
  return { id: OWNER_SENDER, owner: true };
}

function signatureFailure(bridgeKey, agent, incoming, now) {
  const key = decisionKey(bridgeKey);
  if (!key || !agent) return 'the channel has no bridge key or sandbox name: run enclos runtime configure --channel app again';
  if (incoming.host !== true) return 'a signed message from someone other than the host\'s person';
  if (incoming.attachments?.length) return 'a message with files is not signed';
  return checkSigned(key, [LABEL, agent, incoming.conversation, incoming.id, incoming.person, incoming.text], incoming.signed, now);
}
