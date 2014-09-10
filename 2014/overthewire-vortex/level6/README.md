# Vortex 6

Program re-executes itself if there are any environment variables.

The definition of 'itself' is controlled via `argv[0]` which we control, and point at `/bin/sh`.