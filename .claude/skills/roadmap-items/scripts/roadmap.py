#!/usr/bin/env python3
"""roadmap.py -- item-based roadmap/backlog store as markdown-in-git.

Stdlib only. No PyYAML, no third-party deps: the frontmatter is a tiny fixed
shape and a hand-written parser keeps the supply chain empty, which is the whole
point of a "code is liability" project. No subprocess either -- this script only
reads and writes files in the working tree it is run from, and the one git-shaped
operation it offers (emit-patch) is *generated* as text, not shelled out: the
mbox is built directly with difflib/hashlib so the "no subprocess, auditable and
bounded" invariant holds. The actual apply stays with the operator (git am), so
apply == ratify is preserved. Commit/bundle remain the caller's job.

Data model (see references/schema.md for the full spec):

  roadmap/                 visible, one file per item, e.g. item-0042.md
  roadmap/_order.md        the cross-arc global execution order (IDs, line order)
  roadmap/completed/       done items are moved here

  Item frontmatter (canonical field order):
    id, status, arcs, rank, title, goal, acceptance_intent, links,
    execution_profile

  status:  proposed -> ratified -> done
  rank:    numeric-sparse, zero-padded string ("0010", "0020", ...)
  arcs:    list; an item may belong to several arcs (query tags)
  _order:  global item ordering -- arcs are tags, this file decides what runs next
"""

import argparse
import difflib
import email.utils
import hashlib
import os
import re
import sys

REQUIRED_FIELDS = ["id", "status", "arcs", "rank", "title", "goal",
                   "acceptance_intent"]
OPTIONAL_FIELDS = ["links", "execution_profile"]
FIELD_ORDER = REQUIRED_FIELDS + OPTIONAL_FIELDS
QUOTED_SCALARS = {"rank", "title", "goal", "acceptance_intent"}
STATUSES = ["proposed", "ratified", "done"]
LEGAL_FORWARD = {("proposed", "ratified"), ("ratified", "done")}
ID_RE = re.compile(r"^item-(\d+)$")
ORDER_LINE_RE = re.compile(r"^-\s+(item-\d+)\s*$")
RANK_STEP = 10
RANK_WIDTH = 4


# --------------------------------------------------------------------------
# frontmatter parse / serialize
# --------------------------------------------------------------------------

def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _split_commas(inner):
    # Inline lists/maps here never nest and their values never contain commas,
    # so a plain split is correct and keeps the parser trivial.
    return [p for p in (x.strip() for x in inner.split(",")) if p != ""]


def _parse_value(val):
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        return [_unquote(x) for x in _split_commas(val[1:-1])]
    if val.startswith("{") and val.endswith("}"):
        d = {}
        for pair in _split_commas(val[1:-1]):
            k, _, v = pair.partition(":")
            d[k.strip()] = _unquote(v.strip())
        return d
    return _unquote(val)


def parse_item(text):
    """Return (meta dict, body str). Raise ValueError on malformed frontmatter."""
    if not text.startswith("---"):
        raise ValueError("item has no frontmatter (must start with ---)")
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError("item frontmatter is not closed by a second ---")
    fm, body = parts[1], parts[2].lstrip("\n")
    meta = {}
    for raw in fm.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        meta[key.strip()] = _parse_value(val)
    return meta, body


def _format_value(key, v):
    if isinstance(v, list):
        return "[" + ", ".join(v) + "]"
    if isinstance(v, dict):
        return "{ " + ", ".join("%s: %s" % (k, vv) for k, vv in v.items()) + " }"
    s = str(v)
    return '"%s"' % s if key in QUOTED_SCALARS else s


def dump_item(meta, body):
    """Serialize in canonical field order so diffs are stable and reviewable."""
    lines = ["---"]
    for k in FIELD_ORDER:
        if k not in meta:
            continue
        v = meta[k]
        if k in OPTIONAL_FIELDS and v in (None, "", [], {}):
            continue
        lines.append("%s: %s" % (k, _format_value(k, v)))
    # Preserve any unexpected keys rather than silently dropping operator data.
    for k in meta:
        if k not in FIELD_ORDER:
            lines.append("%s: %s" % (k, _format_value(k, meta[k])))
    lines.append("---")
    return "\n".join(lines) + "\n\n" + body.rstrip("\n") + "\n"


def validate_meta(meta):
    missing = [f for f in REQUIRED_FIELDS if f not in meta or meta[f] in (None, "", [])]
    if missing:
        raise ValueError("item is missing required field(s): " + ", ".join(missing))
    if meta["status"] not in STATUSES:
        raise ValueError("status must be one of %s" % STATUSES)
    if not isinstance(meta["arcs"], list) or not meta["arcs"]:
        raise ValueError("arcs must be a non-empty list")
    if not ID_RE.match(meta["id"]):
        raise ValueError("id must look like item-NNNN")


def _is_ascii(text):
    """Return True if text contains only ASCII characters."""
    try:
        text.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False


def validate_ascii(meta, body):
    """Ensure meta and body contain only ASCII characters."""
    for field in ["title", "goal", "acceptance_intent"]:
        if field in meta and not _is_ascii(str(meta[field])):
            raise ValueError("%s contains non-ASCII characters" % field)
    if not _is_ascii(body):
        raise ValueError("item body contains non-ASCII characters")


# --------------------------------------------------------------------------
# store helpers
# --------------------------------------------------------------------------

def completed_dir(root):
    return os.path.join(root, "completed")


def order_path(root):
    return os.path.join(root, "_order.md")


def item_path(root, item_id, completed=False):
    base = completed_dir(root) if completed else root
    return os.path.join(base, item_id + ".md")


def _iter_item_files(root):
    for base in (root, completed_dir(root)):
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            if ID_RE.match(name[:-3] if name.endswith(".md") else name):
                yield os.path.join(base, name)


def load_all(root):
    """Return {id: (meta, body, path)} across active and completed items."""
    out = {}
    for path in _iter_item_files(root):
        with open(path, encoding="utf-8") as fh:
            meta, body = parse_item(fh.read())
        out[meta["id"]] = (meta, body, path)
    return out


def write_item(meta, body, path):
    validate_meta(meta)
    validate_ascii(meta, body)
    if ".." in path:
        raise ValueError("Invalid file path")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(dump_item(meta, body))


def next_id(root):
    nums = [int(ID_RE.match(mid).group(1)) for mid in load_all(root)]
    return "item-%04d" % ((max(nums) + 1) if nums else 1)


def pad_rank(n):
    return str(int(n)).zfill(RANK_WIDTH)


def read_order(root):
    p = order_path(root)
    if not os.path.exists(p):
        return []
    ids = []
    with open(p, encoding="utf-8") as fh:
        for line in fh:
            m = ORDER_LINE_RE.match(line.strip())
            if m:
                ids.append(m.group(1))
    return ids


ORDER_HEADER = (
    "# Execution order (global, cross-arc)\n\n"
    "Items run top to bottom; order is line order. Each line is `- <item-id>`.\n"
    "Items not listed here are unscheduled. `rank` orders items *within* an arc\n"
    "for queries; this file is the cross-arc truth for *what runs next*. IDs only\n"
    "-- titles live in the item files (single source).\n\n"
)


def write_order(root, ids):
    os.makedirs(root, exist_ok=True)
    body = ORDER_HEADER + "".join("- %s\n" % i for i in ids)
    with open(order_path(root), "w", encoding="utf-8") as fh:
        fh.write(body)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def _arc_ranks(items, arc):
    rows = [(m["rank"], mid) for mid, (m, _, _) in items.items() if arc in m["arcs"]]
    return sorted(rows)


def cmd_new(args):
    root = args.root
    arcs = _split_commas(args.arcs)
    if not arcs:
        sys.exit("error: --arcs needs at least one arc")
    items = load_all(root)
    if args.rank:
        rank = pad_rank(args.rank)
    else:
        existing = _arc_ranks(items, arcs[0])
        top = int(existing[-1][0]) if existing else 0
        rank = pad_rank(top + RANK_STEP)
    meta = {
        "id": next_id(root),
        "status": "proposed",
        "arcs": arcs,
        "rank": rank,
        "title": args.title,
        "goal": args.goal,
        "acceptance_intent": args.acceptance,
    }
    if args.links:
        meta["links"] = _split_commas(args.links)
    if args.cls or args.reasoning:
        meta["execution_profile"] = {
            "class": args.cls or "smallest",
            "reasoning": args.reasoning or "none",
        }
    body = (args.note or "Drift-invariant planning notes go here.").strip()
    write_item(meta, body, item_path(root, meta["id"]))
    print("created %s (status: proposed, rank: %s, arcs: %s)"
          % (meta["id"], rank, ", ".join(arcs)))
    print("note: 'new' does not schedule the item. Use 'reorder' to place it in "
          "the execution order once it is ratified.")


def cmd_list(args):
    items = load_all(args.root)
    rows = []
    for mid, (m, _, _) in items.items():
        # Default to the active set. Done items live in completed/ precisely to
        # keep the working list small, so they are hidden unless asked for --
        # either explicitly via --status done or broadly via --all.
        if args.status:
            if m["status"] != args.status:
                continue
        elif not args.all and m["status"] == "done":
            continue
        if args.arc and args.arc not in m["arcs"]:
            continue
        rows.append(m)
    key = (lambda m: m["rank"]) if args.sort == "rank" else (lambda m: m["id"])
    for m in sorted(rows, key=key):
        print("%s  [%-8s] rank=%s  arcs=%s  %s"
              % (m["id"], m["status"], m["rank"], ",".join(m["arcs"]), m["title"]))
    if not rows:
        print("(no matching items)")


def cmd_order(args):
    items = load_all(args.root)
    ids = read_order(args.root)
    if not ids:
        print("(execution order is empty)")
        return
    for pos, mid in enumerate(ids, 1):
        if mid in items:
            m = items[mid][0]
            print("%2d. %s  [%s]  %s" % (pos, mid, m["status"], m["title"]))
        else:
            print("%2d. %s  [MISSING item file]" % (pos, mid))


def cmd_next(args):
    items = load_all(args.root)
    for mid in read_order(args.root):
        m = items.get(mid, (None,))[0]
        if m and m["status"] == "ratified":
            print("next to execute: %s" % mid)
            print("  title:             %s" % m["title"])
            print("  goal:              %s" % m["goal"])
            print("  acceptance_intent: %s" % m["acceptance_intent"])
            print("  arcs:              %s" % ", ".join(m["arcs"]))
            if "links" in m:
                print("  links:             %s" % ", ".join(m["links"]))
            if "execution_profile" in m:
                ep = m["execution_profile"]
                print("  execution_profile: class=%s reasoning=%s (advisory)"
                      % (ep.get("class", "?"), ep.get("reasoning", "?")))
            print("\nAuthor the byte-exact instruction ephemerally against the "
                  "current pin -- do not store it back here.")
            return
    print("(nothing ratified at the top of the execution order)")


def cmd_show(args):
    items = load_all(args.root)
    if args.id not in items:
        sys.exit("error: %s not found" % args.id)
    m, body, _ = items[args.id]
    sys.stdout.write(dump_item(m, body))


def _load_one(root, item_id):
    items = load_all(root)
    if item_id not in items:
        sys.exit("error: %s not found" % item_id)
    return items[item_id]


def cmd_set_status(args):
    m, body, path = _load_one(args.root, args.id)
    old = m["status"]
    new = args.status
    if new == "done":
        sys.exit("error: use 'done' to retire an item (it also writes the final "
                 "summary and moves the file to completed/).")
    if not args.force and (old, new) not in LEGAL_FORWARD:
        sys.exit("error: %s -> %s is not a forward transition. The real gate for "
                 "proposed -> ratified is the operator's ratifying commit/merge; "
                 "this flag-flip rides along with it. Use --force only to correct "
                 "a mistake." % (old, new))
    m["status"] = new
    write_item(m, body, path)
    print("%s: %s -> %s" % (args.id, old, new))


def cmd_update(args):
    m, body, path = _load_one(args.root, args.id)
    if args.title:
        m["title"] = args.title
    if args.goal:
        m["goal"] = args.goal
    if args.acceptance:
        m["acceptance_intent"] = args.acceptance
    links = m.get("links", [])
    for l in _split_commas(args.add_link or ""):
        if l not in links:
            links.append(l)
    for l in _split_commas(args.remove_link or ""):
        if l in links:
            links.remove(l)
    if links:
        m["links"] = links
    elif "links" in m:
        del m["links"]
    if args.cls or args.reasoning:
        ep = m.get("execution_profile", {})
        if args.cls:
            ep["class"] = args.cls
        if args.reasoning:
            ep["reasoning"] = args.reasoning
        m["execution_profile"] = ep
    write_item(m, body, path)
    print("updated %s" % args.id)


def cmd_rank(args):
    m, body, path = _load_one(args.root, args.id)
    if args.to:
        m["rank"] = pad_rank(args.to)
    elif args.between:
        a, b = args.between
        items = load_all(args.root)
        for nid in (a, b):
            if nid not in items:
                sys.exit("error: neighbour %s not found" % nid)
        lo, hi = sorted((int(items[a][0]["rank"]), int(items[b][0]["rank"])))
        mid = (lo + hi) // 2
        if mid <= lo or mid >= hi:
            sys.exit("error: no integer gap between rank %04d and %04d. Run "
                     "'rescale <arc>' to re-space that arc, then retry." % (lo, hi))
        m["rank"] = pad_rank(mid)
    else:
        sys.exit("error: pass --to RANK or --between ID_A ID_B")
    write_item(m, body, path)
    print("%s rank -> %s" % (args.id, m["rank"]))


def cmd_rescale(args):
    items = load_all(args.root)
    ordered = _arc_ranks(items, args.arc)
    if not ordered:
        sys.exit("error: no items in arc %s" % args.arc)
    for i, (_, mid) in enumerate(ordered, 1):
        m, body, path = items[mid]
        new = pad_rank(i * args.step)
        if new != m["rank"]:
            print("  %s: %s -> %s" % (mid, m["rank"], new))
        m["rank"] = new
        write_item(m, body, path)
    print("rescaled arc %s in steps of %d" % (args.arc, args.step))


def cmd_restructure(args):
    m, body, path = _load_one(args.root, args.id)
    arcs = list(m["arcs"])
    if args.arcs:
        arcs = _split_commas(args.arcs)
    for a in _split_commas(args.add_arc or ""):
        if a not in arcs:
            arcs.append(a)
    for a in _split_commas(args.remove_arc or ""):
        if a in arcs:
            arcs.remove(a)
    if not arcs:
        sys.exit("error: an item must belong to at least one arc")
    m["arcs"] = arcs
    write_item(m, body, path)
    print("%s arcs -> %s" % (args.id, ", ".join(arcs)))


def cmd_reorder(args):
    items = load_all(args.root)
    if args.id not in items:
        sys.exit("error: %s not found" % args.id)
    ids = read_order(args.root)
    ids = [i for i in ids if i != args.id]
    if args.remove:
        write_order(args.root, ids)
        print("removed %s from the execution order" % args.id)
        return
    if args.before:
        if args.before not in ids:
            sys.exit("error: anchor %s is not in the execution order" % args.before)
        ids.insert(ids.index(args.before), args.id)
    elif args.after:
        if args.after not in ids:
            sys.exit("error: anchor %s is not in the execution order" % args.after)
        ids.insert(ids.index(args.after) + 1, args.id)
    elif args.to_position is not None:
        pos = max(1, min(args.to_position, len(ids) + 1))
        ids.insert(pos - 1, args.id)
    else:
        ids.append(args.id)
    write_order(args.root, ids)
    print("execution order updated; %s placed" % args.id)


def cmd_done(args):
    m, body, path = _load_one(args.root, args.id)
    if m["status"] != "ratified" and not args.force:
        sys.exit("error: only a ratified item should move to done. Use --force to "
                 "override for a correction.")
    m["status"] = "done"
    summary = "\n\n## Final summary\n\n%s\n" % args.summary.strip()
    body = body.rstrip("\n") + summary
    dest = item_path(args.root, args.id, completed=True)
    write_item(m, body, dest)
    if os.path.abspath(dest) != os.path.abspath(path):
        os.remove(path)
    ids = [i for i in read_order(args.root) if i != args.id]
    write_order(args.root, ids)
    print("%s -> done, moved to completed/, dropped from execution order" % args.id)
    print("commit this with the item id in the message (executor convention).")


# --------------------------------------------------------------------------
# patch emission (git am-consumable mbox, generated as text -- no subprocess)
# --------------------------------------------------------------------------
#
# The output is a one-message mbox in git's own patch shape. The operator applies
# it with `git am`, and *that* apply is the ratifying commit -- so the From:/
# Subject: envelope is load-bearing, not cosmetic. New files are pure additive
# hunks; modified/deleted files use difflib for correct context. Blob SHAs are
# the real git object ids (sha1("blob <len>\0<bytes>")) so `git am -3` can
# 3-way-recover against a drifted tree; with a clean apply they are ignored.

NULL_SHA = "0" * 40
MBOX_POSTMARK = "From %s Mon Sep 17 00:00:00 2001\n" % NULL_SHA
DEFAULT_AUTHOR = "roadmap-bot <roadmap-bot@localhost>"


def blob_sha(data):
    """git blob object id for the given bytes (stdlib, no git needed)."""
    h = hashlib.sha1()
    h.update(b"blob " + str(len(data)).encode("ascii") + b"\0" + data)
    return h.hexdigest()


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def _store_prefix(root):
    # Patch paths must be repo-relative. The store dir is conventionally
    # 'roadmap/'; basename works whether --root is relative or absolute.
    return os.path.basename(os.path.normpath(root))


def _walk_store(storedir):
    """{path-relative-to-store: full-path} for every .md under the store."""
    out = {}
    for dirpath, _dirs, files in os.walk(storedir):
        for name in files:
            if name.endswith(".md"):
                full = os.path.join(dirpath, name)
                out[os.path.relpath(full, storedir)] = full
    return out


def _new_file_hunk(rel, new_bytes):
    lines = new_bytes.decode("utf-8").splitlines(keepends=True)
    out = [
        "diff --git a/%s b/%s\n" % (rel, rel),
        "new file mode 100644\n",
        "index %s..%s\n" % (NULL_SHA, blob_sha(new_bytes)),
        "--- /dev/null\n",
        "+++ b/%s\n" % rel,
        "@@ -0,0 +1,%d @@\n" % len(lines),
    ]
    out += ["+" + ln for ln in lines]
    return out


def _delete_file_hunk(rel, old_bytes):
    lines = old_bytes.decode("utf-8").splitlines(keepends=True)
    out = [
        "diff --git a/%s b/%s\n" % (rel, rel),
        "deleted file mode 100644\n",
        "index %s..%s\n" % (blob_sha(old_bytes), NULL_SHA),
        "--- a/%s\n" % rel,
        "+++ /dev/null\n",
        "@@ -1,%d +0,0 @@\n" % len(lines),
    ]
    out += ["-" + ln for ln in lines]
    return out


def _modify_hunk(rel, old_bytes, new_bytes):
    old_lines = old_bytes.decode("utf-8").splitlines(keepends=True)
    new_lines = new_bytes.decode("utf-8").splitlines(keepends=True)
    body = list(difflib.unified_diff(
        old_lines, new_lines,
        fromfile="a/" + rel, tofile="b/" + rel, lineterm="\n"))
    if not body:
        return []
    return [
        "diff --git a/%s b/%s\n" % (rel, rel),
        "index %s..%s 100644\n" % (blob_sha(old_bytes), blob_sha(new_bytes)),
    ] + body


def _file_hunk(rel, old_bytes, new_bytes):
    if old_bytes is None and new_bytes is not None:
        return _new_file_hunk(rel, new_bytes)
    if old_bytes is not None and new_bytes is None:
        return _delete_file_hunk(rel, old_bytes)
    if old_bytes is not None and new_bytes is not None and old_bytes != new_bytes:
        return _modify_hunk(rel, old_bytes, new_bytes)
    return []


def build_mbox(message, author, date_str, diff_lines):
    """Assemble the one-message mbox. First message line is the subject."""
    msg_lines = (message or "roadmap: update").splitlines() or ["roadmap: update"]
    subject, body = msg_lines[0], msg_lines[1:]
    parts = [
        MBOX_POSTMARK,
        "From: %s\n" % author,
        "Date: %s\n" % date_str,
        "Subject: [PATCH] %s\n" % subject,
        "\n",
    ]
    if body:
        parts += [b + "\n" for b in body]
        parts.append("\n")
    parts.append("---\n\n")
    parts += diff_lines
    return "".join(parts)


def cmd_emit_patch(args):
    root = args.root
    prefix = _store_prefix(root)
    diff_lines = []

    if args.baseline:
        # General mode: diff a pristine store dir against the current one. Catches
        # modifies (_order.md, in-place edits) and the delete+create of a done-move.
        cur = _walk_store(root)
        base = _walk_store(args.baseline)
        for rel in sorted(set(cur) | set(base)):
            old = _read_bytes(base[rel]) if rel in base else None
            new = _read_bytes(cur[rel]) if rel in cur else None
            diff_lines += _file_hunk(os.path.join(prefix, rel), old, new)
        default_msg = "roadmap: update"
    else:
        # Creation mode (the 'new task' path): given item IDs, emit pure additive
        # new-file hunks. No baseline, no git -- the file content is the patch.
        if not args.ids:
            sys.exit("error: pass item IDs (creation mode) or --baseline DIR "
                     "(general mode, for edits/_order/done-moves)")
        for iid in args.ids:
            if not ID_RE.match(iid):
                sys.exit("error: %s is not an item id (expected item-NNNN)" % iid)
            active, done = item_path(root, iid), item_path(root, iid, completed=True)
            full = active if os.path.exists(active) else (
                done if os.path.exists(done) else None)
            if full is None:
                sys.exit("error: %s not found on disk -- create it first" % iid)
            rel = os.path.relpath(full, root)
            diff_lines += _new_file_hunk(os.path.join(prefix, rel),
                                         _read_bytes(full))
        default_msg = "roadmap: add " + ", ".join(args.ids)

    if not diff_lines:
        sys.exit("error: nothing to emit (no changes detected)")

    mbox = build_mbox(args.message or default_msg,
                      args.author or DEFAULT_AUTHOR,
                      email.utils.formatdate(localtime=True),
                      diff_lines)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(mbox)
        print("wrote %s" % args.output)
        print("operator applies (this apply ratifies): git am %s" % args.output)
    else:
        sys.stdout.write(mbox)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(description="item-based roadmap store (markdown-in-git)")
    p.add_argument("--root", default="roadmap", help="store directory (default: roadmap)")
    sub = p.add_subparsers(dest="cmd", required=True)

    n = sub.add_parser("new", help="create a proposed item")
    n.add_argument("--title", required=True)
    n.add_argument("--arcs", required=True, help="comma-separated arc names")
    n.add_argument("--goal", required=True, help="one-line end state")
    n.add_argument("--acceptance", required=True, help="acceptance intent (not greps)")
    n.add_argument("--rank")
    n.add_argument("--links")
    n.add_argument("--class", dest="cls", help="execution_profile class (advisory)")
    n.add_argument("--reasoning", help="execution_profile reasoning depth (advisory)")
    n.add_argument("--note", help="drift-invariant body note")
    n.set_defaults(func=cmd_new)

    l = sub.add_parser("list", help="query items by status/arc, sorted")
    l.add_argument("--status", choices=STATUSES)
    l.add_argument("--arc")
    l.add_argument("--all", action="store_true",
                   help="include done/archived items (default: active only)")
    l.add_argument("--sort", choices=["rank", "id"], default="rank")
    l.set_defaults(func=cmd_list)

    o = sub.add_parser("order", help="show the global execution order")
    o.set_defaults(func=cmd_order)

    nx = sub.add_parser("next", help="show the top ratified item to execute")
    nx.set_defaults(func=cmd_next)

    sh = sub.add_parser("show", help="print a single item verbatim")
    sh.add_argument("id")
    sh.set_defaults(func=cmd_show)

    ss = sub.add_parser("set-status", help="advance status (proposed -> ratified)")
    ss.add_argument("id")
    ss.add_argument("status", choices=STATUSES)
    ss.add_argument("--force", action="store_true")
    ss.set_defaults(func=cmd_set_status)

    up = sub.add_parser("update", help="edit item fields in place")
    up.add_argument("id")
    up.add_argument("--title")
    up.add_argument("--goal")
    up.add_argument("--acceptance")
    up.add_argument("--add-link", dest="add_link")
    up.add_argument("--remove-link", dest="remove_link")
    up.add_argument("--class", dest="cls")
    up.add_argument("--reasoning")
    up.set_defaults(func=cmd_update)

    rk = sub.add_parser("rank", help="reprioritize within an arc")
    rk.add_argument("id")
    rk.add_argument("--to", help="explicit rank")
    rk.add_argument("--between", nargs=2, metavar=("ID_A", "ID_B"))
    rk.set_defaults(func=cmd_rank)

    rs = sub.add_parser("rescale", help="re-space all ranks in one arc")
    rs.add_argument("arc")
    rs.add_argument("--step", type=int, default=RANK_STEP)
    rs.set_defaults(func=cmd_rescale)

    re_ = sub.add_parser("restructure", help="change an item's arc membership")
    re_.add_argument("id")
    re_.add_argument("--arcs", help="replace the whole arc list")
    re_.add_argument("--add-arc", dest="add_arc")
    re_.add_argument("--remove-arc", dest="remove_arc")
    re_.set_defaults(func=cmd_restructure)

    ro = sub.add_parser("reorder", help="move an item in the global execution order")
    ro.add_argument("id")
    ro.add_argument("--before")
    ro.add_argument("--after")
    ro.add_argument("--to-position", type=int, dest="to_position")
    ro.add_argument("--remove", action="store_true", help="unschedule (drop from order)")
    ro.set_defaults(func=cmd_reorder)

    dn = sub.add_parser("done", help="retire a ratified item with a final summary")
    dn.add_argument("id")
    dn.add_argument("--summary", required=True)
    dn.add_argument("--force", action="store_true")
    dn.set_defaults(func=cmd_done)

    ep = sub.add_parser(
        "emit-patch",
        help="emit a git am-consumable mbox patch (stdlib, no git invoked)")
    ep.add_argument("ids", nargs="*",
                    help="item IDs to emit as new-file creations (the 'new task' path)")
    ep.add_argument("--baseline",
                    help="pristine store dir to diff against (general mode: "
                         "edits, _order.md, done-moves)")
    ep.add_argument("-m", "--message",
                    help="commit message; first line becomes the subject")
    ep.add_argument("-o", "--output", help="write patch to FILE (default: stdout)")
    ep.add_argument("--author",
                    help='author "Name <email>"; git am preserves it into the tree')
    ep.set_defaults(func=cmd_emit_patch)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except ValueError as exc:
        sys.exit("error: %s" % exc)


if __name__ == "__main__":
    main()
