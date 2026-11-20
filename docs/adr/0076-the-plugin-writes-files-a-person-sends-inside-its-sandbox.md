---
status: proposed
---

# The plugin writes files a person sends inside its sandbox

Context: a person should be able to send an agent photos and documents with a message from the app (issue #298). The bytes reach the bridge, which runs on the host outside every sandbox, and must end up where the agent's runtime reads them, in the sandbox home. Something has to write them there.

Decision: the agent's channel plugin writes them. The bridge stores the message with its files in its own media folder, as it keeps an agent's files, then sends the plugin `message.in` with the files declared and their bytes in `message.part`s over the plugin's existing socket. The plugin writes them in its own folder of the sandbox home and gives the runtime the message once every byte came. The bridge never writes into a sandbox home, and adds no listener, mount or grant for this. A plugin that does not name `incoming_files` is sent no file: a message with files for it is refused whole, never sent as its text alone. A message's bytes live only as long as the device's connection until it is stored: there is no upload session, resume, upload store or ledger, and a message whose bytes did not all come is dropped and sent again whole ([protocol.md](../protocol.md#sending-files)).

Reason: a host process writing into a folder the sandbox controls must defend every path step against links, renames and races a program of the sandbox can make, with the host's authority; a mistake lands bytes outside the sandbox. The plugin writing inside its sandbox stays under its existing policy and is trusted no more than the agent. The cost is that the bytes cross a second socket, in bounded parts, and are sent again whole after a disconnect, which the limits (4 files of 10 MB) keep small.

Current limitation: completion streams up to 40,000,000 bytes on the device's session thread while holding the plugin output lock. A slow plugin delays that device session and other forwards to the same agent. This proposal does not add a queue or change the threading model.

Retention is partially implemented: recognized completed or abandoned copies expire after 24 hours, checked each minute while listening; successful native conversation deletion removes copies with matching conversation metadata, and cleanup failures require retry. Legacy or incomplete metadata permits expiry but not conversation attribution; unexpected entries and symlinks are preserved. A pending marker protects admitted media until the public processing-complete callback. After restart, an uncertain admission remains indefinitely because the plugin cannot yet bind it to a durable Hermes completion receipt. Thus bounded retention remains unverified for that case; synthetic callback tests are not a real gateway lifecycle proof. Disconnect waits up to five seconds for its owned cleanup worker; timeout retains ownership and fails before teardown. Filesystem enumeration has no successful-completion time bound.
