'''
!!!WARNING!!! THIS CODE IS MARKED AS MALICIOUS BY MODERN AV SOFTWARE SINCE
DYNAMIC ANALYSIS SHOWS THAT PROGRAMM ENCRYPTS FILES WITH AES-GCM WHICH IS A RARE REAL-LIFE SCENARIO, I GUESS.
HOWEVER, THIS CODE IS BUILT FOR PURELY RESEARCH REASONS AND POSSESES NO EVIL WILL.
'''
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from software.demo.encryption_demo import direct_script_main


if __name__ == "__main__":
    direct_script_main("header-only")
