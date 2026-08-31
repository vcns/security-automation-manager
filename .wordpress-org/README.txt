This directory maps directly onto the WordPress.org SVN "assets/" folder --
the deploy pipeline's ASSETS_DIR is .wordpress-org itself, not a subfolder
of it. Place listing files at the TOP LEVEL of this directory, not inside
an "assets/" subfolder (an earlier version of this note said otherwise;
that caused everything to land one directory too deep -- assets/assets/ --
on the actual live SVN repo).

Files here:
- icon-128x128.png, icon-256x256.png (or icon.svg)
- banner-772x250.png, banner-1544x500.png
- screenshot-1.png through screenshot-N.png, captions in readme.txt's
  == Screenshots == section

These files are for the WordPress.org listing and should not be included
in the runtime plugin zip shipped to end users (excluded via .distignore,
same as every other file in this directory).

Do not commit a built release zip or the reviewer-reply draft here --
both are gitignored (.wordpress-org/*.zip, wporg-resubmission-reply-draft.md)
for exactly that reason: this whole directory reaches the live public SVN
listing on every tagged release.
