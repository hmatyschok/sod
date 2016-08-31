Simple sign-on service on demand daemon (sod)
---------------------------------------------

This daemon provides (due to its early implementation status) only 
simple user authentication throught providing an interface for the 
backend of web-applications (or other funny things). 

Further, communication between backend and pam(8) is provided by 
using socket API. Transactions are mapped in AF_UNIX domain. See 

<pre><code>
 https://www.freebsd.org/cgi/man.cgi?query=unix&manpath=FreeBSD+10.3-stable
</code></pre>

for further details. The use of IPC through socket(2) in unix(4) domain 
provides strict isolation between the domain of given backend and pam(8) 
subsystem. 

<pre><code>
 https://www.freebsd.org/cgi/man.cgi?query=pam&manpath=FreeBSD+10.3-stable
</code></pre>

Now, it is up to the pam(8) subsystem to handle (or forward) service 
requests targeting local user data base or remote sites managing user 
credentials. 

Why was not libevent(3) used as proxy pattern performing 
asynchronous I/O on non-blocking unix(4) domain socket?

<pre><code>
 Because to avoid dependencies on external libraries.
</code></pre>

Why was not used select(2) for aynchronous I/O? 

<pre><code>
 Because select(2) scales terribly on
 large amounts by socket(2) allocated
 file descriptors.
</code></pre>

Why was not used kqueue(2)?

<pre><code>
 Because of portability.
</code></pre>

Why is this a forking daemon still using blocking 
streaming socket in unix(4) domain?

<pre><code>
 To hold the implementation as simple as possible.
 
 Any forked child provides for the transaction  
 insulated context by its Process Control Block.    
</code></pre>
 
Additional information about contacting
---------------------------------------
      
If someone wants to contact me by electronic mail, please use encryption.

<pre><code>
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQENBFYMezIBCACo8X47yor6hI3Rwd2vYr+R2f35ZJw1Zq6qzQXYhWhn2CNf4gYJ
5+hEBi5LJcSFhSvujo/xy3OZzL8a4YN/vFWGTZhuyk20MOx96yjzLLbXD9lxHd+a
AoSPuPe78QSTAw7azv7PtUSTnH0KzLCC2Rh1yODYmU4bBw5Aeso/mmWNebh6hd7r
Azp3ruLji1YorWTUHWWDbq+EsB3bSvNq6hmGiOnTsWlhhdOre4ny0OD0Tig6OgFR
S3fkzofnroJN21MdAgofksaeClzdEgSDor1Yk/tcdCHRu4/kHEdEljD6YdpzWbKx
f6BsqMFLHKrksEF8H7oH+Cq3izXOeziy9TsVABEBAAG0Okhlbm5pbmcgTWF0eXNj
aG9rIDxoZW5uaW5nLm1hdHlzY2hva0BzdHVkLmZoLWZsZW5zYnVyZy5kZT6JATcE
EwEIACEFAlYMezICGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQzcSBpLKQ
n3Xocgf8Dcp8MoACABJbUDMHGzFOScLhSugj6zcWZVJ96Uyj1B4yrshk1GiSOid5
OkY+g0BLZDsZ6L/ikY55jh4FMRw6Ox6sh2NX1rT4TVVkJJwiG6KLTwvLpqknaRXX
SoSKRt+U2JYhVLX8UY5TGlqtz5jtUm6jB8i2W64EFXYGl161rELEYmpienHvrFH7
rDMIHdBNlc4bJRiJU/qN5/28+BPjnFmG2/xVv7NlnH01GTPIXx2WfmkcgqNnleZS
d74iTejqFtB3jMws9zSCgLK5G684YeFJbN0mYdnZ+JonwaGti4oV91Ey/1NN0dHH
dgiA/njv+Sf17fwDxHLcj7RMesjZ7bkBDQRWDHsyAQgAyZyyysgBBysI0UqYL/27
1mNWABM3Ok6MinkrCy/oeqvp0zj4xocfzvjqpNEC9R2tzIxCtni+c1T2a4eoLSvu
G2TRrncPxHSxvGCClwQxlkS5INp4Y2NCEq4s+Fo0OyTawXGTTTgNEPK8yviK+0nh
jcpEcCNhGMArkNR6G0W6M2k6v3k0A2fMJ0ARFFj85kpbPv1IMGLs8HbWUe2D/1KQ
rJsCGU5tjiOXYL1/KfXDBhfw+fwC5AM+Ndxlhpla3Z+0RaxCjvQT7Z501U311aMh
kbfmS+Llvq3cZNDleNkWkHsWYgYL4wZqnrVQDfeqzL+moFjBHtLn+ZZbLn6OYc1f
qQARAQABiQEfBBgBCAAJBQJWDHsyAhsMAAoJEM3EgaSykJ91zKoH/jzxQSy7pUZx
Pe4ktFRJwil8g6CGUncVaV+Sxe0A+52dlk85W/4F+wMROvg5tc98uZeLH8Ye0BSI
EDwJD5Iel9qI+qQegqzvGkjuJzZx86XhFWBa8dmIzRgqeAZrblmpv9k5V1cyMSUO
2v/GaJOu3P9Jb9RPR0YVsiZTs3+R1Z6V05pBdbMG5bUVHvjEIFahmHKc+cvxwjPV
wY7U3JsZk7bYZG05pUstLIuNJ//UMVjC/dM6ofKTyLknbKDYKvJvcmPBSSeC7VXg
u5E2GRq1FgrjmjTS8r+/zZfV31iFkIdc5gC9ipwBsA7H6Bx8lPP5M0l1MXS/wAWU
8GZ4NRztiBU=
=lsmx
-----END PGP PUBLIC KEY BLOCK-----
</code></pre>

[![Flattr this git repo](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=hmatyschok&url=https://github.com/hmatyschok/MeshBSD&title=MeshBSD&language=&tags=github&category=software) Please feel free to support me anytime.
