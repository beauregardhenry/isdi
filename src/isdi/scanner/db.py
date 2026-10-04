import logging
import sqlite3
from isdi import crypto
from isdi.config import _restrict_permissions, get_config
from flask import g
from datetime import datetime as dt
import os
import threading
from pathlib import Path

config = get_config()
DATABASE = config.SQL_DB_PATH.replace("sqlite:///", "").strip()
# CONSULTS_DATABASE = config.SQL_DB_CONSULT_PATH.replace('sqlite:///', '')
_thread_local = threading.local()

# The only copy of the schema. Client data columns hold encrypted values
# (isdi/crypto.py), so they carry no CHECK constraints.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS clients_notes (
	id INTEGER NOT NULL,
	created_at DATETIME,
	clientid VARCHAR(100) DEFAULT '' NOT NULL,
	consultant_initials VARCHAR(100) DEFAULT '' NOT NULL,
	fjc VARCHAR(13) DEFAULT '' NOT NULL,
	preferred_language VARCHAR(100) DEFAULT 'English' NOT NULL,
	referring_professional VARCHAR(100) DEFAULT '' NOT NULL,
	referring_professional_email VARCHAR(255),
	referring_professional_phone VARCHAR(50),
	caseworker_present VARCHAR(23) DEFAULT '' NOT NULL,
	caseworker_present_safety_planning VARCHAR(3) DEFAULT '' NOT NULL,
	caseworker_recorded VARCHAR(3) DEFAULT '' NOT NULL,
	recorded VARCHAR(3) DEFAULT '' NOT NULL,
	chief_concerns VARCHAR(400) DEFAULT '' NOT NULL,
	chief_concerns_other TEXT DEFAULT '' NOT NULL,
	android_phones INTEGER DEFAULT '0' NOT NULL,
	android_tablets INTEGER DEFAULT '0' NOT NULL,
	iphone_devices INTEGER DEFAULT '0' NOT NULL,
	ipad_devices INTEGER DEFAULT '0' NOT NULL,
	macbook_devices INTEGER DEFAULT '0' NOT NULL,
	windows_devices INTEGER DEFAULT '0' NOT NULL,
	echo_devices INTEGER DEFAULT '0' NOT NULL,
	other_devices VARCHAR(400) DEFAULT '',
	checkups VARCHAR(400) DEFAULT '',
	checkups_other VARCHAR(400) DEFAULT '',
	vulnerabilities VARCHAR(600) DEFAULT '' NOT NULL,
	vulnerabilities_trusted_devices TEXT DEFAULT '',
	vulnerabilities_other TEXT DEFAULT '',
	safety_planning_onsite VARCHAR(14) DEFAULT '' NOT NULL,
	changes_made_onsite TEXT DEFAULT '',
	unresolved_issues TEXT DEFAULT '',
	follow_ups_todo TEXT DEFAULT '',
	general_notes TEXT DEFAULT '',
	case_summary TEXT DEFAULT '',
	PRIMARY KEY (id)
);

CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  clientid TEXT,
  location TEXT,
  issues TEXT,
  assessment TEXT,
  plan TEXT,
  the_rest TEXT,
  time DATETIME DEFAULT (datetime('now', 'localtime'))
);

CREATE TABLE IF NOT EXISTS scan_res (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  clientid TEXT,
  serial TEXT,
  note TEXT,
  device TEXT,
  device_model TEXT,
  device_manufacturer TEXT,
  device_version TEXT,
  is_rooted INTEGER,
  rooted_reasons TEXT,
  last_full_charge DATETIME,
  device_primary_user TEXT,
  device_access TEXT,
  how_obtained TEXT,
  time DATETIME DEFAULT (datetime('now', 'localtime')),
  operator TEXT,
  FOREIGN KEY(clientid) REFERENCES clients_notes(clientid)
);

CREATE TABLE IF NOT EXISTS app_info (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scanid INTEGER,
  appid TEXT,
  flags TEXT,
  remark TEXT,
  action_taken TEXT,
  apk_path TEXT,
  install_date DATETIME,
  last_updated DATETIME,
  app_version TEXT,
  permissions TEXT,
  permissions_reason TEXT,
  permissions_used DATETIME,
  data_usage INTEGER,
  battery_usage INTEGER,
  details TEXT,
  time DATETIME DEFAULT (datetime('now', 'localtime')),
  FOREIGN KEY(scanid) REFERENCES scan_res(id)
);

CREATE INDEX IF NOT EXISTS idx_clients_notes_clientid on clients_notes (clientid);
CREATE INDEX IF NOT EXISTS idx_scan_res_clientid on scan_res (clientid);
CREATE INDEX IF NOT EXISTS idx_app_info_scanid on app_info (scanid);

-- Append-only record of who did what (isdi/audit.py). Each entry's mac
-- covers the previous entry's, so removed or altered entries are detected.
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  time TEXT NOT NULL,
  operator TEXT,
  action TEXT NOT NULL,
  clientid TEXT,
  scanid INTEGER,
  details TEXT,
  details_mac TEXT,
  prev TEXT NOT NULL,
  mac TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_clientid on audit_log (clientid);

-- Raw dumps kept, encrypted, when the operator asks for an evidence copy
-- (isdi/evidence.py). dump_sha256 is the hash at the time of the scan;
-- unredacted is 1 when account email addresses were not blanked out.
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scanid INTEGER NOT NULL,
  clientid TEXT,
  created TEXT NOT NULL,
  dump_name TEXT,
  dump_sha256 TEXT NOT NULL,
  size INTEGER,
  data TEXT,
  unredacted INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(scanid) REFERENCES scan_res(id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_scanid on evidence (scanid);
"""


# Columns holding client data, encrypted at rest. Everything else is an id,
# the non-identifying client counter (YYYYMMDD_NNN), the HMAC of a serial,
# the device type (android/ios) or a timestamp, which queries need.
ENCRYPTED_COLUMNS = {
    "clients_notes": (
        "consultant_initials fjc preferred_language referring_professional "
        "referring_professional_email referring_professional_phone "
        "caseworker_present caseworker_present_safety_planning "
        "caseworker_recorded recorded chief_concerns chief_concerns_other "
        "android_phones android_tablets iphone_devices ipad_devices "
        "macbook_devices windows_devices echo_devices other_devices checkups "
        "checkups_other vulnerabilities vulnerabilities_trusted_devices "
        "vulnerabilities_other safety_planning_onsite changes_made_onsite "
        "unresolved_issues follow_ups_todo general_notes case_summary"
    ).split(),
    "clients": "location issues assessment plan the_rest".split(),
    "scan_res": (
        "note device_model device_manufacturer device_version is_rooted "
        "rooted_reasons last_full_charge device_primary_user device_access "
        "how_obtained operator"
    ).split(),
    "app_info": (
        "appid flags remark action_taken apk_path install_date last_updated "
        "app_version permissions permissions_reason permissions_used "
        "data_usage battery_usage details"
    ).split(),
    "audit_log": "operator details".split(),
    "evidence": "dump_name data".split(),
}
# Bumped by migrate(); stored in the database's PRAGMA user_version.
SCHEMA_VERSION = 4


def _enc(column, value):
    return crypto.encrypt(column, value)


def _schema_needs_init(db) -> bool:
    cur = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='clients_notes'"
    )
    return cur.fetchone() is None


def _init_schema(db) -> None:
    db.executescript(SCHEMA_SQL)
    db.commit()


def today():
    return dt.now().strftime("%Y%m%d")


def new_client_id():
    """Today's date and a counter: 20260101_001, 20260101_002, ...

    Counts only today's ids in that format, so an id written some other way
    (or a created_at in another time zone) cannot break or repeat it."""
    prefix = today() + "_"
    rows = query_db(
        "select clientid from clients_notes where substr(clientid, 1, ?) = ?",
        (len(prefix), prefix),
    )
    counters = [
        int(r["clientid"][len(prefix) :])
        for r in rows
        if r["clientid"][len(prefix) :].isdigit()
    ]
    return "{}{:03d}".format(prefix, max(counters, default=0) + 1)


def make_dicts(cursor, row):
    """Rows as dicts, with encrypted values decrypted."""
    return {
        col[0]: crypto.decrypt(col[0], value)
        for col, value in zip(cursor.description, row)
    }


def _connect():
    db = sqlite3.connect(DATABASE)
    _restrict_permissions(Path(DATABASE), 0o600)
    db.row_factory = make_dicts
    # Overwrite deleted rows instead of leaving them in free pages, so that
    # erased client data is gone from the file.
    db.execute("PRAGMA secure_delete = ON")
    return db


def get_db():
    try:
        db = getattr(g, "_database", None)
        if db is None:
            logging.debug("Opening database %s", DATABASE)
            db = g._database = _connect()
            if _schema_needs_init(db):
                _init_schema(db)
        return db
    except RuntimeError:
        if not hasattr(_thread_local, "db") or _thread_local.db is None:
            logging.debug("Opening thread-local database %s", DATABASE)
            _thread_local.db = _connect()
            if _schema_needs_init(_thread_local.db):
                _init_schema(_thread_local.db)
        return _thread_local.db


def close_db(exc=None):
    """Close this app context's connection (registered as a teardown)."""
    db = g.pop("_database", None)
    if db is not None:
        db.close()


def init_db(app, sa, force=False):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        if force or _schema_needs_init(db):
            _init_schema(db)
        migrate(db)


def _columns(db, table):
    return [r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]


def migrate(db) -> None:
    """Bring a database from before encryption at rest up to date:
    encrypt existing client data, drop the CHECK constraints that encrypted
    values cannot meet, and rewrite the file so no plaintext pages remain.
    Safe to run on every start."""
    # Raw tuples here: the usual row factory decrypts, which is not wanted.
    factory, db.row_factory = db.row_factory, None
    try:
        _migrate(db)
    finally:
        db.row_factory = factory


def _migrate(db) -> None:
    (version,) = db.execute("PRAGMA user_version").fetchone()
    if version >= SCHEMA_VERSION:
        return
    # Columns and tables added since the database was created.
    if "details" not in _columns(db, "app_info"):
        db.execute("ALTER TABLE app_info ADD COLUMN details TEXT")
    if "operator" not in _columns(db, "scan_res"):
        db.execute("ALTER TABLE scan_res ADD COLUMN operator TEXT")
    audit = SCHEMA_SQL[SCHEMA_SQL.index("CREATE TABLE IF NOT EXISTS audit_log") :]
    db.executescript(audit)
    if "unredacted" not in _columns(db, "evidence"):
        db.execute(
            "ALTER TABLE evidence ADD COLUMN unredacted INTEGER NOT NULL DEFAULT 0"
        )
    sql = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='clients_notes'"
    ).fetchone()[0]
    if "CHECK" in sql:
        # SQLite cannot drop a constraint: rebuild the table, same columns.
        create = SCHEMA_SQL[
            SCHEMA_SQL.index("CREATE TABLE IF NOT EXISTS clients_notes") :
        ]
        create = create[: create.index(");") + 2]
        db.execute("ALTER TABLE clients_notes RENAME TO clients_notes_old")
        db.execute(create)
        db.execute("INSERT INTO clients_notes SELECT * FROM clients_notes_old")
        db.execute("DROP TABLE clients_notes_old")
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_clients_notes_clientid "
            "ON clients_notes (clientid)"
        )
    for table, cols in ENCRYPTED_COLUMNS.items():
        rows = db.execute(f"SELECT id, {', '.join(cols)} FROM {table}").fetchall()
        for row in rows:
            plain = {
                c: v
                for c, v in zip(cols, row[1:])
                if v is not None and not crypto.is_encrypted(v)
            }
            if plain:
                sets = ", ".join(f"{c}=?" for c in plain)
                db.execute(
                    f"UPDATE {table} SET {sets} WHERE id=?",
                    [_enc(c, v) for c, v in plain.items()] + [row[0]],
                )
    db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    db.commit()
    if version < 1:
        # The old plaintext is still in the file's free pages until rewritten.
        db.execute("VACUUM")
        logging.info("Database migrated: client data is encrypted")


def insert(query, args):
    db = get_db()
    cur = db.execute(query, args)
    lrowid = cur.lastrowid
    cur.close()
    db.commit()
    return lrowid


def insert_many(query, argss):
    db = get_db()
    cur = db.executemany(query, argss)
    lrowid = cur.lastrowid
    cur.close()
    db.commit()
    return lrowid


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    lrowid = cur.lastrowid
    cur.close()
    return (rv[0] if rv else None) if one else rv


def save_note(scanid, note):
    insert("update scan_res set note=? where id=?", args=(_enc("note", note), scanid))
    return True


def create_scan(scan_d):
    """
    @scanr must have following fields.
    """
    return insert(
        "insert into scan_res "
        "(clientid, serial, device, device_model, device_version, device_manufacturer, last_full_charge, device_primary_user, is_rooted, rooted_reasons, operator) "
        "values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        args=(
            scan_d["clientid"],
            scan_d["serial"],
            scan_d["device"],
            _enc("device_model", scan_d["device_model"]),
            _enc("device_version", scan_d["device_version"]),
            _enc("device_manufacturer", scan_d["device_manufacturer"]),
            _enc("last_full_charge", scan_d["last_full_charge"]),
            _enc("device_primary_user", scan_d["device_primary_user"]),
            _enc("is_rooted", scan_d["is_rooted"]),
            _enc("rooted_reasons", scan_d["rooted_reasons"]),
            _enc("operator", scan_d.get("operator")),
        ),
    )


def app_row_ids(scanid) -> dict:
    """appid -> row id for one scan. App ids are encrypted (with a random
    nonce), so rows are matched after decrypting, not in SQL."""
    rows = query_db("select id, appid from app_info where scanid=?", (scanid,))
    return {r["appid"]: r["id"] for r in rows}


def update_appinfo(scanid, appid, remark, action):
    rowid = app_row_ids(scanid).get(appid)
    if rowid is None:
        return False
    insert(
        "update app_info set remark=?, action_taken=? where id=?",
        args=(_enc("remark", remark), _enc("action_taken", action), rowid),
    )
    return True


def update_mul_appinfo(args):
    """args: (remark, scanid, appid) tuples."""
    ids = {}
    updates = []
    for remark, scanid, appid in args:
        if scanid not in ids:
            ids[scanid] = app_row_ids(scanid)
        rowid = ids[scanid].get(appid)
        if rowid is not None:
            updates.append((_enc("remark", remark), rowid))
    return insert_many("update app_info set remark=? where id=?", updates)


def create_mult_appinfo(args, details=None):
    """args: (scanid, appid, flags, remark, action_taken) tuples. details:
    appid -> what the phone's dump said about the app, kept so the dump
    itself need not be."""
    details = details or {}
    return insert_many(
        "insert into app_info (scanid, appid, flags, remark, action_taken, details) "
        "values (?,?,?,?,?,?)",
        [
            (
                scanid,
                _enc("appid", appid),
                _enc("flags", flags),
                _enc("remark", remark),
                _enc("action_taken", action),
                _enc("details", details.get(appid)),
            )
            for scanid, appid, flags, remark, action in args
        ],
    )


def app_details_from_scan(scanid, appids) -> dict:
    """appid -> the dump details stored with that scan."""
    wanted = set(appids)
    rows = query_db(
        "select appid, details from app_info where scanid=?", args=(scanid,)
    )
    return {r["appid"]: r["details"] or {} for r in rows if r["appid"] in wanted}


def get_client_devices_from_db(clientid: str) -> list:
    # Return one (latest) scan row per serial for this client.
    d = query_db(
        "select sr.id, sr.device, sr.device_model, sr.serial, sr.device_primary_user "
        "from scan_res sr "
        "join ("
        "  select serial, max(id) as max_id "
        "  from scan_res "
        "  where clientid=? and serial is not null and serial <> '' "
        "  group by serial"
        ") latest on sr.id = latest.max_id "
        "order by sr.id desc",
        args=(clientid,),
        one=False,
    )
    if d:
        return d
    else:
        return []


def get_most_recent_scan_id(ser: str) -> int:
    d = query_db(
        "select max(id) as scanid from scan_res where serial=?", args=(ser,), one=True
    )
    print(f"Get_most_recent_scanid: {d}")
    return d["scanid"]


def get_scan_res_from_db(scanid):
    d = query_db("select * from scan_res where id=?", args=(scanid,), one=True)
    return d


def get_app_info_from_db(scanid):
    d = query_db("select * from app_info where scanid=?", args=(scanid,), one=False)
    if d:
        return d
    else:
        return []


def get_clientid_for_scan(scanid):
    d = query_db("select clientid from scan_res where id=?", args=(scanid,), one=True)
    return d["clientid"] if d else None


def get_device_from_db(scanid):
    d = query_db("select device from scan_res where id=?", args=(scanid,), one=True)
    if d:
        return d["device"]
    else:
        return ""


def get_serial_from_db(scanid):
    d = query_db("select serial from scan_res where id=?", args=(scanid,), one=True)
    if d:
        return d["serial"]
    else:
        return ""


def first_element_or_none(l):
    if l and len(l) > 0:
        return l[0]


def delete_scan_data(serial: str) -> bool:
    """
    Delete all data for a scanned device identified by its stored serial.
    Removes app_info rows, scan_res rows, and any dump files on disk.
    Returns True on success.
    """
    import glob
    import shutil

    db_conn = get_db()

    # Get all scan IDs for this serial
    scan_ids = query_db(
        "SELECT id FROM scan_res WHERE serial=?", args=(serial,), one=False
    )
    if scan_ids:
        for row in scan_ids:
            db_conn.execute("DELETE FROM app_info WHERE scanid=?", (row["id"],))
            db_conn.execute("DELETE FROM evidence WHERE scanid=?", (row["id"],))
        db_conn.execute("DELETE FROM scan_res WHERE serial=?", (serial,))
        db_conn.commit()
        from isdi import audit

        ids = [row["id"] for row in scan_ids]
        audit.erase_scan_details(ids)
        audit.record(
            "device_data_deleted", details={"serial_hmac": serial, "scans": ids}
        )

    # Remove dump files: stored as <serial>_<device_type>.<ext> inside DUMP_DIR
    dump_dir = config.DUMP_DIR
    for fpath in glob.glob(
        os.path.join(glob.escape(dump_dir), f"{glob.escape(serial)}_*")
    ):
        try:
            if os.path.isdir(fpath):
                shutil.rmtree(fpath)
            else:
                os.remove(fpath)
        except OSError:
            pass

    return True


def export_client(clientid) -> dict:
    """Everything stored about one client, decrypted (for a GDPR access or
    portability request): consultation notes, and each scan with its apps."""
    scans = query_db(
        "select * from scan_res where clientid=? order by id", args=(clientid,)
    )
    for scan in scans:
        scan["apps"] = query_db(
            "select * from app_info where scanid=? order by id", args=(scan["id"],)
        )
    from isdi import audit

    return {
        "clientid": clientid,
        "notes": query_db(
            "select * from clients_notes where clientid=? order by id", (clientid,)
        ),
        "scans": scans,
        "audit_log": audit.entries(clientid),
        # The newest entry of the whole log when this export was made: a
        # log rebuilt or cut short afterwards no longer matches it.
        "audit_head": audit.head(),
    }


def erase_client(clientid) -> dict:
    """Delete everything stored about one client (GDPR erasure). Returns
    how many rows were deleted from each table."""
    db = get_db()
    scanids = [
        r["id"]
        for r in query_db("select id from scan_res where clientid=?", (clientid,))
    ]
    counts = {"app_info": 0}
    for scanid in scanids:
        counts["app_info"] += db.execute(
            "DELETE FROM app_info WHERE scanid=?", (scanid,)
        ).rowcount
    counts["scan_res"] = db.execute(
        "DELETE FROM scan_res WHERE clientid=?", (clientid,)
    ).rowcount
    counts["clients_notes"] = db.execute(
        "DELETE FROM clients_notes WHERE clientid=?", (clientid,)
    ).rowcount
    counts["clients"] = db.execute(
        "DELETE FROM clients WHERE clientid=?", (clientid,)
    ).rowcount
    counts["evidence"] = db.execute(
        "DELETE FROM evidence WHERE clientid=?", (clientid,)
    ).rowcount
    db.commit()
    from isdi import audit

    counts["audit_details"] = audit.erase_client_details(clientid)
    return counts
