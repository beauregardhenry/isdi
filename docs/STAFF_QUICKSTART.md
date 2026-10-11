# ISDi quick start for advocates

One session with one client, from start to finish. For installing ISDi and
the commands supervisors use, see the [README](../README.md).

## Before the client arrives

- Start ISDi (`isdi run`) and enter the passphrase. Open
  <http://localhost:6200> and sign in with **your own** account. Never share
  accounts: everything you do is recorded under your name.
- **Each sign-in starts a new client.** If the home page shows devices
  scanned for someone else, sign out and sign in again.
- If the home page says a newer ISDi is available, ask whoever looks
  after ISDi to update it before you rely on a scan.
- You are signed out after 15 minutes without using ISDi. Signing in again
  within 2 hours continues with the same client (from ISDi 1.10.0).

## With the client

1. **Talk about safety first.** Before touching the phone, explain what the
   check can and cannot show, and agree that nothing will be removed today
   without a safety plan.
2. **Decide about evidence before scanning.** If the client may go to court
   (a protective order, a family or criminal case), tick **Keep an
   encrypted evidence copy**. It cannot be added afterwards. For Android,
   ask a supervisor before ticking **keep it unredacted**: it keeps the email
   addresses of every account on the phone, which may be other people's.
3. **Prepare the phone.** Open **Scan Instructions**. An iPhone needs to be
   unlocked, then **Trust** tapped. An Android phone needs USB debugging
   turned on.
4. **Scan.** Choose Android or iOS, give the phone a nickname (whose it
   is, never the client's full name), and click **Scan now**. Connect one
   phone at a time, and leave it connected while you look at app details.
5. **Go through the results together** with **Summary for the client**.
   Show it on screen. Print it only if the client wants a copy and has
   somewhere safe to keep it.
6. **Do not uninstall anything** (the ⊗ in the Uninstall column) unless
   the client has a safety plan and has decided to. Removing an app can
   alert whoever installed it, and destroys evidence.
7. **Privacy Checkup** goes through the phone's built-in sharing settings,
   such as location sharing: on Android it opens each settings screen; for
   an iPhone it lists where to look.
8. **Consultation record** keeps the questionnaire, the accounts checked,
   the questions about each app, screenshots and notes. Prefer **Take one
   from the connected Android phone** to uploading a photo: it is better
   evidence.

## What the results mean

- **A flagged app** is on a list of apps that can be used to monitor
  someone. It does not prove that someone is monitoring the client.
- **"Apps with powerful permissions"** are often ordinary apps (password
  managers, smartwatch apps). Check together that the client recognises
  each one.
- **Nothing found** does not mean nobody is watching. Someone who knows the
  client's passwords can see a lot from their online accounts, with no app
  on the phone. Check the accounts too.

## Before the client leaves

- **The take-home copy** (Consultation record → **Open the take-home
  copy**) leaves out the client's name, your notes and the names of the
  clinic and of ISDi. **en español** gives it in Spanish. The Spanish has not
  yet been reviewed by a native speaker, so read it first if you can. A
  PDF can have a password: tell the client the password in person.
- On Android, check that USB debugging is turned off again before the phone
  leaves.
- **Sign out**, so that the next session starts with a new client. At the
  end of the day, **Close App and End Session** stops ISDi.

## If something goes wrong

Ask whoever looks after ISDi. To report a problem, use the **Something is
wrong** form at <https://github.com/beauregardhenry/isdi/issues/new/choose>.
Issues are public, so never include anything about a client.
