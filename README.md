Fork of packerid.py

Added some functionality that might be useful.

Added a userdb.txt that I put together because who doesn't need another one.

There's a parsing issue with pefile currently. You _might_ need to change
line 423 of peutils.py from:
<code>if value == '??' or value == '?0' :</code>
to
<code>if '?' in value:</code>
to get the included userdb.txt file to load correctly.
