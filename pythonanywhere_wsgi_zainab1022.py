import os
import sys

path = "/home/zainab1022/mysite"
app_path = "/home/zainab1022/mysite/fixed_asset_register"

if path not in sys.path:
    sys.path.insert(0, path)
if app_path not in sys.path:
    sys.path.insert(0, app_path)

os.chdir(app_path)

from app import app as application
