"""
make_icon.py -- convert assets/Icarus_logo.png (any assets/icarus*.png) into
assets/icarus.ico so the built IcarusUnfollower.exe carries the winged logo as
its file/taskbar icon.

    python make_icon.py

Needs Pillow (`pip install pillow`). Safe to skip -- the exe still builds
without an icon; this just makes it pretty. build_exe.bat picks the .ico up
automatically if it exists.
"""
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DST = os.path.join(HERE, "assets", "icarus.ico")


def _find_src():
    for pat in (os.path.join(HERE, "assets", "icarus.png"),
                os.path.join(HERE, "assets", "[Ii]carus*.png"),
                os.path.join(HERE, "[Ii]carus*.png")):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    return None


def main():
    SRC = _find_src()
    if not SRC:
        print(f"Put the logo in {os.path.join(HERE, 'assets')} (name it icarus*.png), then re-run.")
        sys.exit(1)
    try:
        from PIL import Image
    except ImportError:
        print("Pillow not installed. Run:  pip install pillow")
        sys.exit(1)
    im = Image.open(SRC).convert("RGBA")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    im.save(DST, sizes=sizes)
    print(f"Wrote {DST}")


if __name__ == "__main__":
    main()
