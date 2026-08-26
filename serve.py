from __future__ import annotations

import uvicorn

from web.app import create_app

HOST = "127.0.0.1"
PORT = 8765

app = create_app()


def main() -> None:
    print(f"PSR dashboard: http://{HOST}:{PORT}")
    print("Loopback only. Browser-triggered security runs are disabled.")
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        access_log=False,
    )


if __name__ == "__main__":
    main()
