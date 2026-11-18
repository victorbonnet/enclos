---
status: proposed
---

# Each host sends push through FCM with a key its user gives it

[ADR 0042](0042-a-bridge-on-each-host-serves-the-mobile-app.md) sends notifications through FCM, from the host, with the preview encrypted for the device (`docs/protocol.md`, Notifications). Sending through FCM needs a Google service-account key of the Firebase project the app was built with, and whoever holds it can send to every device of that app. That key cannot be given to every host. Today the host's user is the only person ([ADR 0043](0043-sharing-an-agent-is-not-hosting-it.md)), and the person who runs the hosts also builds the app.

Decision (proposed):

- **The bridge sends directly to FCM.** It uses FCM's HTTP v1 API, signed in as a service account whose key the host's user gives it. No service of enclos's stands between them. Sending to Google is the bridge's first connection off the host. No sandbox gets a new route.
- **A dedicated, narrow key.** The service account belongs to the app's Firebase project and holds one permission, `cloudmessaging.messages.create`, through a custom role. It is never the Firebase Admin SDK's own account, which can do much more. `enclos app push key <file>` reads the key from that file and checks that it is a service-account key. It keeps the key's project id and writes the key to `app-push-key.json` in enclos's data folder, `0600`, hidden from every sandbox like the bridge's other keys. Setting or removing the key is an audit entry. The key itself is never printed or logged.
- **Push is optional.** Without a key, the bridge sends nothing, and `enclos app status` says push is off. The phone gets what arrived at its next sync. A notification is never the record: the bridge keeps the history, as before.
- **A push proves nothing on its own.** The app shows no notification for a preview that does not open under its own device's `push_key`. A stolen sender key lets someone wake the app's phones, but not make them show words.

Reason: the person who builds the app holds its Firebase project and runs every host that needs push today, so a key on each host works with nothing more to run and no third party but Google. A narrow key on a host the user owns limits what a leak gives away. The design is only correct while each host's user holds a key for the app's project. That covers the app's publisher and anyone who builds the app with a Firebase project of their own.

## Considered options

- **A push service the app's publisher runs**, which holds the key and forwards each host's pushes. Anyone could get push with the official app without a Google account of their own. But it is one more service to run and keep up, it sees every host's traffic timing, and hosts need a way to authenticate to it. It becomes needed when the app is published for people other than its builder, and a new ADR will then amend or supersede this one.
- **Keeping the connection open on the phone** (a foreground service): no Google involved. But it needs a status notification that never goes away and costs battery. Doze cuts its network unless the person exempts the app from battery optimization, and iOS has no equivalent. It may come later as a setting for phones without Google Play services. UnifiedPush is another way to reach such phones; both would sit beside FCM, not replace it.
- **The key in the secret store** (Keychain, libsecret): the secret store holds a sandbox's secrets. Reading the Keychain from a launchd service is still to verify (design §14), and the bridge's other keys are files in the data folder.

## Consequences

- Google sees which device tokens a host's project sends to, and when: the host's name, a number, and ciphertext of one size. It does not see the text.
- A key for another project than the device's app is refused by FCM (`SENDER_ID_MISMATCH`). The bridge records each refusal in `enclos app log`, and `enclos app status` shows push failing for that device. When FCM reports a token unregistered, the bridge drops it until the device sends a new one with `push.token`.
- To rotate the key, revoke it in Google Cloud and run `enclos app push key` with the new one.
- The bridge needs an HTTPS client, and RS256 signing for the token it exchanges with Google for an access token.
- The protocol's high-priority data message does not carry over to iOS, where background pushes may be delayed or dropped. The iOS payload is decided when iOS is built (milestone 4 leaves iOS out).
