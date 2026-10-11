# Spanish review packet

`spanish-review.csv` holds every Spanish text ISDi shows a client, next to
its English: the client summary page and the take-home copy of the
consultation report. The translation has **not yet been reviewed by a
native speaker who works with clients**. Until it has, staff should read
the Spanish copy before giving it to a client.

## For the reviewer

Open `spanish-review.csv` in Excel, LibreOffice or Google Sheets. Each row is
one text:

| Column | What it is |
| --- | --- |
| `where` | Where the text appears (client summary, take-home copy; heading, question, answer choice or risk) |
| `english` | The English it translates |
| `spanish` | The Spanish ISDi shows now |
| `suggested_spanish` | **Your correction.** Leave it empty if the Spanish is fine |
| `notes` | Anything else: a question, a regional alternative, a concern |

Leave `source` and `key` as they are: they say where the text lives in the
code. Save the file as CSV (UTF-8) and attach it to the **Spanish
translation review** form:
<https://github.com/beauregardhenry/isdi/issues/new?template=2-translation-review.yml>.
Issues are public: write about the words, never about clients.

What to look for, in order of importance:

1. **Anything that could put a client at risk or mislead them**, for example
   advice that reads as "remove the app now", or wording that makes a
   finding sound like proof.
2. **Anything a client would not understand**: technical words, or Spanish
   that reads as translated.
3. Wording that is correct but could be plainer or warmer.

### Conventions used so far

Change these if they are wrong for the people you serve, and say so in
`notes`:

- The client is addressed as **usted**.
- "The client" is **la persona atendida** and "the person of concern" is
  **la persona que le preocupa**: both are gender-neutral.
- "Advocate" is **intercesor(a)**.
- "Two-factor authentication" is **verificación en dos pasos**; "rooting"
  and "jailbreak" are kept as **root** and **jailbreak**.

### Keep these exactly

- Words in braces, such as `{phone}`, `{n}` and `{org}`: ISDi replaces them
  with the phone's name, a number or an organisation. Move them within the
  sentence if needed, but keep each one.
- The tags `<strong>` and `</strong>` (bold text).

A correction that drops or adds one of these is refused when it is applied,
and nothing is changed until it is fixed.

### Not in the spreadsheet

Two texts are built around a name and live in the code
(`src/isdi/consultation/i18n.py`, `translator`). Comment on them in an email:

- "Risk from app: *name*" is "Riesgo de la aplicación: *name*".
- "Risks identified: *A*, *B*." is "Riesgos encontrados: *A*, *B*."

What staff or the client typed (notes, account and app names) is never
translated.

## For maintainers

Regenerate the packet after changing any Spanish or English text (a test
fails until you do):

```
python scripts/translation_review.py export docs/review/spanish-review.csv
```

Apply a reviewed file:

```
python scripts/translation_review.py apply reviewed.csv
```

This writes each `suggested_spanish` into `src/isdi/client_summary.py` and
`src/isdi/consultation/i18n.py` and runs black. Then run the tests (the
Spanish take-home copy is rendered in strict mode), export the packet again,
and record the review in the CHANGELOG: who reviewed it (with their
permission), and when. Once reviewed, update the notes in
`consultation/i18n.py` and `client_summary.py` that say the Spanish has not
been reviewed.
