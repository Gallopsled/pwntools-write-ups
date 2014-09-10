# Vortex 9

So you're supposed to just search around a bit.  There aren't any interesting setuid binaries.

Most of the files don't stand out.  However, ones stands alone and doesn't have 20 others like it.


```
$ find . 2>/dev/null | grep vort
...
./var/mail/vortex9
...
$ cat ./var/mail/vortex9
5WT0}swdc
```

Tada.
