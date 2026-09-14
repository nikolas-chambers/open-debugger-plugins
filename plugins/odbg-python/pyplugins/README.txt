Plugin drop-folder for odbg-python.

Drop any .py file here and it becomes an odbg plugin the next time the
debugger's Plugins menu is opened (or after "Reload scripts") - no build, no
restart. Files starting with "_" are treated as private modules and ignored.

Two reference plugins to get you started are built into this folder from
../examples/ (complete_plugin.py exercises the full python_sdk; apilog.py is a
working API-call logger). See ../README.md for the Python plugin contract.