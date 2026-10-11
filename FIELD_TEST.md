# Field test: checking ISDi against real phones

ISDi's tests use made-up phone output. Some checks have never been
confirmed on real phones, and phones differ by manufacturer and version:

- Android: apps holding accessibility, notification access or device
  administrator powers (1.8.0);
- iPhone: supervision and configuration profiles (1.8.0), the jailbreak
  check's USB signal ("afc2", repaired in 1.7.0), app names (1.8.1);
- Termux: the two iPhone checks above when ISDi runs on an Android phone
  (1.9.1).

`isdi field-test` runs every check on a connected phone and prints what each
part of ISDi recognised. Sending that report back is how these checks get
confirmed or fixed.

## Use a test phone, never a client's

Use a spare phone or your own. The report holds **no app ids, app or account
names, profile names, serial numbers or email addresses**: only versions,
which parts of the phone's answer were present and their sizes, how many
entries each check recognised, and the names of the fields in Apple's
answers (never their values). ISDi checks the report for the phone's app ids
and serial before printing it, and refuses to print it if one is there.
Nothing is written to ISDi's database or audit log, and the phone's dump is
deleted when the test ends.

Read the report before sending it: it is plain text.

## Android (about 10 minutes)

1. Turn on USB debugging (see ISDi's scan instructions) and connect the
   phone. Allow the computer when the phone asks.
2. So that each check has something to find, set up at least one of each
   (undo them afterwards if you like):
   - an app with an **accessibility service** turned on: Settings →
     Accessibility, turn on any installed service (a password manager or
     an automation app);
   - an app with **notification access**: Settings → Notifications →
     Notification access (or "Device & app notifications"), allow one app
     (a smartwatch or messaging companion app);
   - a **device administrator**: Settings → Security → Device admin apps
     (the name varies), turn one on, for example Find My Device.
3. Run:

   ```
   isdi field-test android -o android-report.txt
   ```

4. Write down, next to the report, what you set up in step 2 (for example
   "1 accessibility service, 1 notification listener, Find My Device as
   admin"), and the phone's make, model and Android version if the report
   shows "Unknown".

## iPhone (about 10 minutes)

1. Connect the iPhone, unlock it and tap **Trust**.
2. If you can, install a **configuration profile** first: many VPN apps and
   school or work email setups install one (Settings → General → VPN &
   Device Management shows them). A supervised iPhone (from a school or
   employer) is especially useful, if one is available for testing.
3. Run:

   ```
   isdi field-test ios -o iphone-report.txt
   ```

4. Write down, next to the report: how many profiles Settings → General →
   VPN & Device Management lists, whether the phone is supervised (the top
   of the Settings app says "This iPhone is supervised and managed by …"),
   and whether it is jailbroken (almost certainly not).

## Termux (ISDi on an Android phone)

Run the iPhone steps from Termux with the iPhone connected to the Android
phone. The report's `environment` section shows `"termux": true`.

## What to look for, and what to send

Send the report file and your notes to the maintainers (open an issue at
<https://github.com/beauregardhenry/isdi/issues>, or email them). Things that
mean a check needs fixing:

- Android: `secure_settings` shows `"present": false` although you turned a
  power on, or `apps_per_power` is missing a power you set up;
  `device_policy_section` is false, or `enabled_device_admins_heading` is
  false with an admin turned on.
- iPhone: `management.read` is false (its `error` says why); `profiles`
  differs from what Settings shows; `parsed.supervised` is wrong;
  `name_taken_from` counts only `CFBundleExecutable`.
- `afc2.error` on a phone that is not jailbroken is normal (the phone
  refuses the service). A `TimeoutError` usually means the phone was locked.
