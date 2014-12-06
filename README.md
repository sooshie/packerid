Fork of packerid.py

Additional output types, and formats, digital signature extraction, and disassembly support

Added a userdb.txt that I put together because who doesn't need another one.

There's a parsing issue with pefile currently. You _might_ need to change line 423 of peutils.py from:
<br/>
<code>if value == '??' or value == '?0' :</code>
<br/>
to
<br/>
<code>if '?' in value:</code>
<br/>
to get the included userdb.txt file to load correctly.

requires:<br/>
* <a href="https://code.google.com/p/pefile/">pefile</a>
* <a href="http://www.capstone-engine.org/">Capstone</a>
