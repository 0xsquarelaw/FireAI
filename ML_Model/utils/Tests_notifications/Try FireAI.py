import time
from winotify import Notification, audio
import winotify
r= winotify.Registry("fifthScan", winotify.PY_EXE,r"c:\abs\path\to\script.py")
notifier= winotify.Notifier(r)
@notifier.register_callback
def funcion2():
    print("hola")
incentives="fifthScan"
toast= Notification(
    app_id=incentives,
    title="Example",
    msg="This is an example message",
    duration="long",
)
toast.add_actions(label="Publisher",launch=funcion2)
toast.show()
