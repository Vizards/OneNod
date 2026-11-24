# Fill a Chrome form on macOS

Use the optional OneNod Form Fill app when the user asks to sign in to a site
or fill a web form from the `Agent` vault. Run its CLI on the Mac that hosts
the target Chrome profile, under the same macOS user. If the browser is on
another Mac, run the commands there. Locate `form-fill` on PATH or use its
installed path (for example, `~/.local/bin/form-fill`).

1. Open the user's intended page in Chrome. Inspect its exact URL, the CSS
   selectors for the target fields, and the submit control if needed. The
   destination page can read any value filled into it.
2. Run `~/.onenod/bin/may preflight` before the first OneNod operation, then
   `~/.onenod/bin/may catalog search '<service>'`. Use the matching item's ID
   and field IDs to build the references. The host requests approved values
   through `may` and delivers them to Chrome. The agent receives status.
3. Probe the page and pass one selector and reference per field. The example
   assumes `form-fill` is on PATH. Replace the URL, selectors and IDs with
   those for the requested login.

```sh
form-fill probe --url 'https://example.org/login'
form-fill fill --url 'https://example.org/login' \
  --field 'input[name=email]' 'op://Agent/<item-id>/<username-field-id>' \
  --field 'input[type=password]' 'op://Agent/<item-id>/<password-field-id>' \
  --submit 'button[type=submit]'
```

If multiple tabs match, use the intended `--session` and `--tab` from
`probe`. For a form inside an iframe, inspect its destination and pass its
exact URL with `--frame-url`. Omit `--submit` for a fill-only request. For
multi-step logins, inspect and fill each step as it appears.

Confirm login using a signed-in page marker, for example
`form-fill verify --url 'https://example.org/account' --text 'Account overview'`.
Use the same session and tab when the login redirects in place.
`submit_dispatched` only confirms the click was dispatched. If the connection
drops during submission, check the current page before retrying.

If the CLI reports `no_extension_connected`, check that the native host is
registered for Chrome and the extension is enabled in the intended profile.
Click its toolbar icon to reconnect. For `no_matching_tab`, check the profile
and exact page URL. If the CLI, connection, or OneNod approval is unavailable,
report which step failed and keep field values out of agent-visible output.
