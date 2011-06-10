[curve25519](http://cr.yp.to/ecdh.html) is an elliptic curve, developed by [Dan Bernstein](http://cr.yp.to/djb.html), for fast [Diffie-Hellman](http://en.wikipedia.org/wiki/Diffie-Hellman) key agreement. DJB's [original implementation](http://cr.yp.to/ecdh.html) was written in a language of his own devising called [qhasm](http://cr.yp.to/qhasm.html). The original qhasm source isn't available, only the x86 32-bit assembly output.

Since many x86 systems are now 64-bit, and portability is important, this project provides alternative implementations for other platforms. 

#### Performance (On an E5200 @ 2.5ghz)
<table>
<thead><tr><th>Implementation</th><th>Platform</th><th>Author</th><th>32-bit speed</th><th>64-bit speed</th><th>Constant time</th></tr></thead>
<tbody>
<tr><td>curve25519</td><td>x86 32-bit</td><td>djb</td><td>244&mu;s</td><td>N/A</td><td>yes</td></tr>
<tr><td>curve25591-donna (old)</td><td>32-bit C</td><td>agl</td><td>2078&mu;s</td><td>551&mu;s</td><td>no</td></tr>
<tr><td>curve25591-donna</td><td>32-bit C</td><td>multiple</td><td>662&mu;s</td><td>281&mu;s</td><td>yes</td></tr>
<tr><td>curve25519-donna-c64 (old)</td><td>64-bit C</td><td>agl</td><td>N/A</td><td>215&mu;s</td><td>yes</td></tr>
<tr><td>curve25519-donna-c64</td><td>64-bit C</td><td>multiple</td><td>N/A</td><td>113&mu;s</td><td>yes</td></tr>
</tbody>
</table>

#### Usage

The usage is exactly the same as djb's code (as described at http://cr.yp.to/ecdh.html) except that the function is called curve25519_donna.

To generate a private key, generate 32 random bytes and: 

	mysecret[0] &= 248;
	mysecret[31] &= 127;
	mysecret[31] |= 64;

To generate the public key:


	static const uint8_t basepoint[32] = {9};
	curve25519_donna(mypublic, mysecret, basepoint);

And hash the shared_key with a cryptographic hash function before using.

For more information, see [djb's page](http://cr.yp.to/ecdh.html)

#### Papers

[djb's curve25519 paper](http://cr.yp.to/ecdh/curve25519-20060209.pdf)