# Legal Use and Compliance — Payload Capture Suite

Owner: Avimanyu Singh Chauhan — rockniraj311@gmail.com — @avimanyusingh53

Network monitoring is regulated almost everywhere. This page summarises the
duties that normally apply. It is general information, not legal advice.

## 1. The core rule

Capture traffic only where you have a lawful basis. In practice that means one
of:

- you own the network and the endpoints on it;
- you administer the network on behalf of its owner, within your job scope;
- you hold signed authorisation for a defined scope, target list and time window;
- every participant in the communication has consented;
- you are acting under a lawful order or warrant.

Ownership of the cable or the access point is not, on its own, authority to read
the content of other people's communications.

## 2. Frequently relevant law

| Jurisdiction | Typically relevant instruments |
| --- | --- |
| India | Information Technology Act 2000 (ss. 43, 66, 69), Telegraph Act 1885, DPDP Act 2023 |
| European Union | GDPR, ePrivacy Directive, national interception statutes |
| United Kingdom | Computer Misuse Act 1990, Investigatory Powers Act 2016, UK GDPR |
| United States | Wiretap Act (18 U.S.C. § 2511), Computer Fraud and Abuse Act, state consent laws |
| Canada | Criminal Code s. 184, PIPEDA |
| Australia | Telecommunications (Interception and Access) Act 1979, Privacy Act 1988 |

Penalties for unauthorised interception commonly include imprisonment as well as
fines.

## 3. Workplace monitoring

Where an employer monitors staff traffic, most regimes additionally require:

- a written, published monitoring policy;
- notice to employees before monitoring begins;
- proportionality — the least intrusive method that achieves the purpose;
- a defined retention period and secure storage;
- special care around health, union, legal and personal correspondence.

## 4. Handling captured personal data

Captured packets are personal data when they can be linked to a person. Treat
them accordingly: minimise what you collect, restrict access, encrypt at rest,
log who opened what, and delete on schedule. The audit log in this software
supports the access-logging part, not the rest.

## 5. Evidence and chain of custody

For output to be useful in a proceeding, keep a record of:

1. who authorised the capture, and the scope of that authority;
2. which machine and interface captured it, and when;
3. the SHA-256 hash of every exported file, recorded at export time;
4. every person who has since held a copy;
5. the software version that produced the report.

The suite records items 2 to 5 automatically. Item 1 is yours to keep.

## 6. Security testing

If you use the scanning-related features against a third party, confirm the
engagement has a signed scope, a named technical contact, an agreed test window
and a documented rollback plan.

## 7. Export and cryptography rules

Some jurisdictions restrict possession or export of network-interception
software. Confirm your local position before carrying the tool across borders.

## 8. When in doubt

Stop, document what you have, and take qualified legal advice before you
continue. An unlawful capture cannot be made lawful afterwards.
