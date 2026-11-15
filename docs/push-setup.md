# Setting up push

Push lets a host reach your phone while the enclos app is closed: when an agent answers, asks a question or asks for a runtime approval and none of your devices is connected, the host's bridge sends a push through Firebase Cloud Messaging (FCM), and the phone shows a notification. Without it, the app shows what came the next time you open it.

Push needs two things from one Firebase project ([ADR 0065](adr/0065-each-host-sends-push-through-fcm-with-a-key-its-user-gives-it.md), proposed; enclos-app ADR 0010, proposed):

- **The app** is built with that project's settings, so the phone gets a token for that project.
- **Each host** holds a service-account key of that project, which can send through FCM and nothing else.

A host's key works only for phones whose app was built with the same project. So whoever builds the app sets up the project, and gives each of their hosts its key. FCM costs nothing, and none of this needs a paid Google account.

What reaches Google: the host's name, a number, and the preview sealed for your phone alone, of one size whatever it says. Google never sees what an agent wrote.

Not shown yet: a push going through Google to a phone. The bridge's side and the app's side are built and tested against stand-ins; the end-to-end run is still to verify (design §14).

## 1. Create the Firebase project

1. Open the [Firebase console](https://console.firebase.google.com) and **Create a project** (or add Firebase to a Google Cloud project you already have).
2. Google Analytics is not needed: turn it off.

A project made in a Google Workspace or Cloud organization created since May 2024 may refuse service-account keys (the organization policy `iam.managed.disableServiceAccountKeyCreation`, on by default there). A project under a personal Google account has no organization, and is not affected. If step 4 says keys are disabled, an organization administrator has to allow them for this project.

## 2. Register the Android app and build it with the settings

1. In the project, add an **Android** app. The package name is `io.github.victorbonnet.enclos`. The nickname is yours; the SHA-1 certificate is not needed for FCM.
2. Download `google-services.json`. Keep it out of every repository: the app does not use the file itself, only four of its values.
3. Write them to `~/.android/enclos-firebase.properties` on the machine that builds the app:

   | Setting | In `google-services.json` |
   | --- | --- |
   | `applicationId` | `client[0].client_info.mobilesdk_app_id` |
   | `apiKey` | `client[0].api_key[0].current_key` |
   | `projectId` | `project_info.project_id` |
   | `senderId` | `project_info.project_number` |

   ```properties
   applicationId=1:123456789012:android:0123456789abcdef
   apiKey=AIza...
   projectId=your-project
   senderId=123456789012
   ```

   With `jq`:

   ```bash
   jq -r '"applicationId=\(.client[0].client_info.mobilesdk_app_id)
   apiKey=\(.client[0].api_key[0].current_key)
   projectId=\(.project_info.project_id)
   senderId=\(.project_info.project_number)"' google-services.json > ~/.android/enclos-firebase.properties
   ```

4. Build the app as usual (`just android` in enclos-app). A file elsewhere can be named with `ENCLOS_FIREBASE_PROPERTIES`. For CI builds, put the file in the `ENCLOS_FIREBASE_PROPERTIES_B64` secret of the enclos-app repository:

   ```bash
   base64 -i ~/.android/enclos-firebase.properties | gh secret set ENCLOS_FIREBASE_PROPERTIES_B64 -R victorbonnet/enclos-app
   ```

   These values are not secret (every APK carries them); they are kept out of git only so the repository names no project. Without them, the app builds with push off.

5. Install the build, open it once, and allow notifications when it asks (Android 13 and later). It then gives each host its token at the next connection.

## 3. Check that the FCM API is on

In the Firebase console, **Project settings**, **Cloud Messaging**: **Firebase Cloud Messaging API (V1)** should say **Enabled**, as it does for a new project. If it does not, its menu opens it in the Google Cloud console, where **Enable** turns it on.

## 4. Make a key that can only send

Firebase's own **Service accounts** tab offers **Generate new private key** for its Admin SDK account. Do not use that one: it can manage much of the project. Make a service account that can only send:

With the Google Cloud console (the same project, under **IAM & Admin**):

1. **Roles**, **Create role**: title `enclos push`, with the single permission `cloudmessaging.messages.create`. Create it.
2. **Service accounts**, **Create service account**: name `enclos-push`. Grant it the `enclos push` role. Create it.
3. Open the account, **Keys**, **Add key**, **Create new key**, **JSON**. The key file downloads; Google keeps no copy you can download again.

Or with `gcloud`, for project `your-project`:

```bash
gcloud iam roles create enclosPush --project=your-project \
  --title="enclos push" --permissions=cloudmessaging.messages.create
gcloud iam service-accounts create enclos-push --project=your-project --display-name="enclos push"
gcloud projects add-iam-policy-binding your-project \
  --member=serviceAccount:enclos-push@your-project.iam.gserviceaccount.com \
  --role=projects/your-project/roles/enclosPush
gcloud iam service-accounts keys create enclos-push.json \
  --iam-account=enclos-push@your-project.iam.gserviceaccount.com
```

The key file is a secret: whoever holds it can wake every phone of your app's project (though not make them show words, since each preview opens only with its own phone's key). Move it to each host over a private channel, such as `scp`, never through a chat or a repository.

## 5. Give the key to each host

On each host:

```bash
enclos app push key enclos-push.json
rm enclos-push.json
```

enclos checks the file, keeps its own copy (`app-push-key.json` in its data folder, readable by you alone and by no sandbox), and records the change in its audit log. A running bridge takes it at its next push, with no restart. `enclos app status` then says `Push: on, through FCM for project your-project.`, and, for each paired device, `push none` until it gives a token, then `push ready`.

`enclos app push off` removes the key: the bridge sends no push from then on.

## 6. Check that it works

1. With the app open, check that the host shows the phone as `push ready` in `enclos app status`.
2. Ask an agent something that takes a while, then leave the app (the home screen is enough: it closes its connections in the background, which is what lets the host push).
3. The answer should arrive as a notification titled with the agent's name. Tapping it opens the conversation.

When nothing comes, `enclos app status` and `enclos app log` on the host say why:

| What it says | What to do |
| --- | --- |
| `Push: off. Give the bridge a key…` | Step 5 on this host. |
| `Push: off: … cannot be used: …` | The file in enclos is not a service-account key: give the one from step 4 again. |
| `push none` for the phone | The phone gave no token: the app was built without the settings of step 2, has no Google Play services, or has not connected since it got one. |
| `…another Firebase project… (SENDER_ID_MISMATCH)` | The host's key and the app's build are for different projects. Use one project for both. |
| `Google refused the push key (400/401/403)` | The key was deleted or disabled, or its account lost the role: make a new key (step 4). |
| `FCM answered 403 PERMISSION_DENIED` | The role lacks `cloudmessaging.messages.create`, or the API is off (step 3). |
| `Google's token endpoint is unavailable (503)` | Google's side; the next push tries again. The message is in the app at its next sync either way. |
| `push token dropped` in the log | FCM no longer knows the phone's token (the app was removed or its data cleared). It gives a new one when it next connects. |

On the phone: no notification while the app is open is expected (the host does not push to a connected device). With the app lock on, a notification says only "New message". When notifications are refused in Android's settings for enclos, nothing shows.

## Replace or revoke the key

To replace it, make a new key for the same account (step 4, the last command or **Add key**), give it to each host with `enclos app push key`, then delete the old key in the console (**Keys**, the old one, delete). A key that leaks is revoked the same way: deleting it in the console stops it at once.
