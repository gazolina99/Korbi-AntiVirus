import tkinter.messagebox as messagebox


def notify_local(title: str, body: str) -> None:
    # Local popup only: keeps app fully offline.
    try:
        messagebox.showwarning(title, body)
    except Exception:
        pass
