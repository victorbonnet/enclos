---
status: proposed
---

# The plugin writes files a person sends inside its sandbox

Context: a person should be able to send an agent photos and documents with a message from the app (issue #298). The bytes reach the bridge, which runs on the host outside every sandbox, and must end up where the agent's runtime reads them, in the sandbox home. Something has to write them there.

Decision: the agent's channel plugin writes them. The bridge stores the message with its files in its own media folder, as it keeps an agent's files, then sends the plugin `message.in` with the files declared and their bytes in `message.part`s over the plugin's existing socket. The plugin writes them in its own folder of the sandbox home and gives the runtime the message once every byte came. The bridge never writes into a sandbox home, and adds no listener, mount or grant for this. A plugin that does not name `incoming_files` is sent no file: a message with files for it is refused whole, never sent as its text alone. A message's bytes live only as long as the device's connection until it is stored: there is no upload session, resume, upload store or ledger, and a message whose bytes did not all come is dropped and sent again whole ([protocol.md](../protocol.md#sending-files)).

Reason: a host process writing into a folder the sandbox controls must defend every path step against links, renames and races a program of the sandbox can make, with the host's authority; a mistake lands bytes outside the sandbox. The plugin writing inside its sandbox stays under its existing policy and is trusted no more than the agent. The cost is that the bytes cross a second socket, in bounded parts, and are sent again whole after a disconnect, which the limits (4 files of 10 MB) keep small.
