# Sphinx configuration for the ebpf-syscall documentation.
#
# The prose docs are hand-written reStructuredText that Read the Docs
# builds into a searchable site (viewable where htmlpreview is not). The
# rich, dark-themed standalone HTML pages under docs/*.html are the
# showcase; they are preserved verbatim so the existing htmlpreview and
# gallery blob links keep working, AND copied into this build under
# /showcase/ so they are reachable at the Read the Docs URL too.
import glob
import os
import shutil

project = "ebpf-syscall"
author = "the ebpf-syscall authors"
copyright = "2026, the ebpf-syscall authors"

extensions = ["sphinx_rtd_theme"]
html_theme = "sphinx_rtd_theme"
html_title = "ebpf-syscall"

# docs/*.html are showcase pages, not RST sources; keep the build tree clean.
exclude_patterns = ["_build", "_extra", "*.html"]

# Publish the standalone showcase HTML (and its images) under /showcase/
# without moving the originals, so blob/htmlpreview links stay valid.
_here = os.path.dirname(os.path.abspath(__file__))
_showcase = os.path.join(_here, "_extra", "showcase")
if os.path.isdir(_showcase):
    shutil.rmtree(_showcase)
os.makedirs(_showcase)
for _html in glob.glob(os.path.join(_here, "*.html")):
    shutil.copy(_html, _showcase)
_img = os.path.join(_here, "img")
if os.path.isdir(_img):
    shutil.copytree(_img, os.path.join(_showcase, "img"))
html_extra_path = ["_extra"]
