# pwntools-write-ups

A collection of CTF write-ups all using pwntools

## Dependencies

- libc++1 (2014/gits-teaser/citadel)
- pwntools (master branch from github, and ofc. all dependencies for pwntools)

## Known Issues

Some of the tests are a bit finnicky, both due to pwntools and the services themselves.

- Some services cannot be re-run immediately (services without REUSEADDR)
- Services that aren't working:
  -  2013/pctf/ropasaurus
  -  2014/defcon-quals/babyfirst-heap
  -  2014/defcon-quals/bbgp

If other tests are failing or there are other issues (e.g. services still running after the test), then please file an issue.
