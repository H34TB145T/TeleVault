# Signed TeleVault updates

TeleVault includes Tauri's signature-verifying updater, but the ordinary local build intentionally has no update endpoint or public key. Never put the private signing key in this repository or in `tauri.conf.json`.

Before publishing releases:

1. Generate and securely back up the Tauri updater signing key. Treat losing the private key as permanent loss of the update channel.
2. Copy `src-tauri/tauri.updater.example.conf.json` to an ignored release-only config and replace the public key and HTTPS endpoint.
3. Configure Apple Developer ID signing and notarization for macOS. The updater signature does not replace platform code signing.
4. Build with the release config and the private key supplied only through the release secret store:

   ```sh
   TELEVAULT_UPDATE_PUBLIC_KEY=1 \
   TELEVAULT_UPDATE_ENDPOINT=https://updates.example.com \
   TAURI_SIGNING_PRIVATE_KEY="$TAURI_SIGNING_PRIVATE_KEY" \
   TAURI_SIGNING_PRIVATE_KEY_PASSWORD="$TAURI_SIGNING_PRIVATE_KEY_PASSWORD" \
   npm run tauri build -- --config src-tauri/tauri.updater.conf.json
   ```

5. Publish the generated updater artifacts, signatures, and Tauri update JSON over HTTPS. Test an upgrade from the previous public version before announcing the release.

The two `TELEVAULT_UPDATE_*` variables are non-secret build markers that make the Settings page expose the update check. The actual endpoint and public key still come from the release config. The private key must exist only in the release environment.
