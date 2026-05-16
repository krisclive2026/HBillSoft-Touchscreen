import webview
import os
import sys
 
def resource_path(filename):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
 
class Api:
    def close_window(self):
        window.destroy()
 
api = Api()
 
html_file = resource_path('RestoPOS.html')
 
window = webview.create_window(
    title='HBILLSOFT',
    url='file:///' + html_file.replace('\\', '/'),
    width=1280,
    height=800,
    min_size=(1024, 600),
    resizable=True,
    fullscreen=True,
    js_api=api
)
 
webview.start()