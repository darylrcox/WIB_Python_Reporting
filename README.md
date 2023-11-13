# WIB Python Reporting tools

## Code Repository

This code repository contains several WIB tools written in Python.

All tools will display their command 'help':

    > python3.10 <Tool-Name>.py --help

All tools will run under version 3 of Python (Python 3.7+). 
Python (for your OS) can be downloaded from: https://www.python.org/downloads/

Some of the tools have extra Python package requirements. Make sure you have
the latest version of 'pip'. From a 'elevated' (Admin) command prompt, run

    > python3.10 -m pip install pip

If this complains that you already have 'pip' installed but should upgrade, run

    > python3.10 -m pip install --upgrade pip

If the terminal complains that 'python3.10' is not found, try just 'python'.

To apply the required packages, run

    > pip install <package-name>

On Windows, the following 'extra' pip install commands may need to be issued:

    > pip install ...

## Tool Functions

--- Tools Listing ---

1) WIBPlatformDataFetch3.py           - 'Fetches' WIB Platform data via the Rest API producing a JSON data file.
2) WIBPlatformDataRawJsonReporter1.py - Consumes the WIB Platform JSON data file (from #1) and produces a PDF (raw output) report.
                                    
## Tool #1 Notes (CxProjectCreator#)

1) ...

--- Extra Package requirement(s) ---

Run 'pip install <package-name>' for:

1) aiohttp
2) bson
3) reportlab

--- Source File(s) for the Tool(s) ---

    --- Commands ---
 1) WIBPlatformDataFetch3.py
 2) WIBPlatformDataRawJsonReporter1.py

    --- Classes ---
 3) ...

    --- Grephics ---
 4) WIB_header_image.jpg

--- Documentation File(s) for the Tool(s) ---

 1) README.md - Extra Documentation for all tools.



