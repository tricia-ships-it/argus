"""
wsgi.py, entry point for running Argus under a production WSGI server
(waitress on Windows, gunicorn/uWSGI on Linux).

It makes sure the database exists, then exposes `app` as the WSGI callable. On
a brand-new install there are no accounts yet, so the first person to open
Argus in a browser is taken to a setup page to create their own administrator
account.

    Windows:  waitress-serve --listen=0.0.0.0:8080 wsgi:app
    Linux:    gunicorn --bind 0.0.0.0:8080 wsgi:app
"""
from app import app, init_db, _ensure_send_worker, _ensure_scan_scheduler

# Idempotent: creates the tables if they're missing. Returns True on a fresh
# install (no accounts yet).
_setup_needed = init_db()
# Start the phishing send worker so scheduled / interrupted jobs resume.
# NOTE: single-process servers only (waitress, gunicorn -w 1). For multiple
# web workers, see docs/phishing-delivery.md (one worker per process).
_ensure_send_worker()
# Start the recurring scan scheduler (network-only scans). Single-process only.
_ensure_scan_scheduler()
if _setup_needed:
    print("\n" + "=" * 64)
    print("  FIRST RUN, no accounts exist yet.")
    print("  Open Argus in your browser and create your administrator account.")
    print("  After that, add your team under 'Users'. Each one sets their own")
    print("  password the first time they sign in.")
    print("=" * 64 + "\n", flush=True)

# `app` is imported above and is the WSGI application object the server runs.

if __name__ == "__main__":
    # Allow `python wsgi.py` to serve with waitress directly, if installed.
    try:
        from waitress import serve
    except ImportError:
        raise SystemExit(
            "waitress is not installed. Install it with:  pip install waitress\n"
            "or run the development server instead:         python app.py"
        )
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    print(f"Argus serving on http://{args.host}:{args.port}  (production server)")
    serve(app, host=args.host, port=args.port)
