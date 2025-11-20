# Reporting Security Issues

If you found a security issue, then I'd like to ask you to fully disclose the details of your valuable findings via GitHub Security Advisory [Report a Vulnerability](https://github.com/mbuesch/httun/security/advisories/new) tab or report it privately via [security@bues.ch] to me.

If you found a severe security vulnerability, a private disclosue is preferred.
This is to protect our users from [0-Day](https://en.wikipedia.org/wiki/Zero-day_vulnerability) exploits.
I will always publish vulnerabilities to the public after finding a proper fix.

# Security analysis

The program has carefully been designed to be secure, to the best of my knowledge.

However, nobody is infallible.

- Please read the code and comment on it.
- Feel free to open an issue, if you have questions, suggestions or requests.
- Please discuss the pros and cons of the design decisions.

I am interested to hear your opinion.

If you found a security vulnerability, see [the vulnerability reporting process](SECURITY.md) for how to proceed.

# Security concept

Strong AES-GCM AEAD encryption and authentication is always used for all packets sent over the tunnel.
The use of HTTPs is *not* required for secure communication.
The protocol is completely decoupled from HTTP/HTTPs and it merely uses HTTP/HTTPs as a dumb transport layer.

Currently only symmetric encryption is supported.
That means the client and the server machine share a common secret.
This is known to be not ideal and future plans include the introduction of some kind of asymmetric key handling in addition to the symmetric key handling.
