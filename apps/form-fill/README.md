# OneNod Form Fill

OneNod Form Fill is an optional macOS app for filling web forms in Chrome. An agent supplies the page URL, CSS selectors, and OneNod field references. The extension fills the selected fields after OneNod authorizes the reads. The same command works with usernames, passwords, and custom fields on HTTP and HTTPS pages. Pass `--submit` when the agent should also click the page's submit button.

## Install in Chrome

1. Install and enroll OneNod on the Mac that runs Chrome. Run `~/.onenod/bin/may preflight` before the first OneNod operation.
2. Keep this app in a persistent directory. From that directory, run `./form-fill install-host` to register the Native Messaging host with Google Chrome. The registration records the absolute path to the executable.
3. In the Chrome profile the agent will use, open `chrome://extensions`, enable **Developer mode**, and select **Load unpacked**. Choose the app's `extension/` directory.
4. Open the target page and run `./form-fill probe --url '<page-url>'`. A `matches` response lists the connected browser session and tab IDs for that URL.

The commands below assume the current directory contains `form-fill` and `extension/`. In a source checkout, this is `apps/form-fill/`.

### Chrome for Testing

For an isolated browser profile, register the host in the same user data directory that Chrome for Testing will use. Set `chrome_for_testing` to the path of the official Chrome for Testing executable.

```sh
lab_profile="$HOME/Library/Application Support/OneNod Form Fill/Lab Chrome"
./form-fill install-host --browser testing --user-data-dir "$lab_profile"
"$chrome_for_testing" --user-data-dir="$lab_profile" --load-extension="$PWD/extension" 'https://example.org/login'
```

## Fill a form

Inspect the page for its exact URL and selectors. Use `may catalog search` to identify the item and field references. Run the CLI on the same Mac and under the same macOS user as Chrome.

```sh
./form-fill probe --url 'https://example.org/login'
./form-fill fill --url 'https://example.org/login' \
  --field 'input[type=email]' 'op://Agent/<item>/<username-field>' \
  --field 'input[type=password]' 'op://Agent/<item>/<password-field>' \
  --submit 'button[type=submit]'
./form-fill verify --url 'https://example.org/account' --text 'Account overview'
```

- If multiple tabs or profiles match the URL, pass the `--session` and `--tab` values returned by `probe`.
- Each selector must match one editable input, textarea, or contenteditable element. The extension also searches open shadow roots. For a form inside an iframe, pass its exact URL with `--frame-url`. The extension binds the operation to that document and checks the target again before filling.
- For a multi-step login, call `fill` on each page. Omit `--submit` to leave the fields filled for a later action.
- `submit_dispatched` means the extension dispatched a click. Verify the destination URL and visible text on the signed-in page to confirm login. If the connection drops during submission, check the page before retrying.
- If the CLI reports `no_extension_connected`, click the extension's toolbar icon to reconnect. The extension also retries automatically.

## Credential handling and trust

Chrome allows the extension ID in the native host manifest to connect to the host. The local CLI sends selectors and field references over a Unix socket in the user's private directory. The host asks the extension to locate the document and fields before invoking `~/.onenod/bin/may read --no-newline`. Approved values travel over Chrome's Native Messaging channel and an internal extension message to the form. The CLI receives progress and status messages.

Processes running under the same macOS user can initiate requests. OneNod's existing approval rules apply to each field read. The caller chooses the destination for each operation, and the destination page can read the values entered in its form. The local caller, native host, extension, browser, and destination site are all part of the credential-handling path.
