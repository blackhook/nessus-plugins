#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1571. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(32305);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-0166");
  script_xref(name:"DSA", value:"1571");

  script_name(english:"Debian DSA-1571-1 : openssl - predictable random number generator");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Luciano Bello discovered that the random number generator in Debian's
openssl package is predictable. This is caused by an incorrect
Debian-specific change to the openssl package (CVE-2008-0166 ). As a
result, cryptographic key material may be guessable.

This is a Debian-specific vulnerability which does not affect other
operating systems which are not based on Debian. However, other
systems can be indirectly affected if weak keys are imported into
them.

It is strongly recommended that all cryptographic key material which
has been generated by OpenSSL versions starting with 0.9.8c-1 on
Debian systems is recreated from scratch. Furthermore, all DSA keys
ever used on affected Debian systems for signing or authentication
purposes should be considered compromised; the Digital Signature
Algorithm relies on a secret random value used during signature
generation.

The first vulnerable version, 0.9.8c-1, was uploaded to the unstable
distribution on 2006-09-17, and has since that date propagated to the
testing and current stable (etch) distributions. The old stable
distribution (sarge) is not affected.

Affected keys include SSH keys, OpenVPN keys, DNSSEC keys, and key
material for use in X.509 certificates and session keys used in
SSL/TLS connections. Keys generated with GnuPG or GNUTLS are not
affected, though.

A detector for known weak key material will be published at :

 (OpenPGP signature)

Instructions how to implement key rollover for various packages will
be published at :

 https://www.debian.org/security/key-rollover/

This website will be continuously updated to reflect new and updated
instructions on key rollovers for packages using SSL certificates.
Popular packages not affected will also be listed.

In addition to this critical change, two other vulnerabilities have
been fixed in the openssl package which were originally scheduled for
release with the next etch point release: OpenSSL's DTLS (Datagram
TLS, basically 'SSL over UDP') implementation did not actually
implement the DTLS specification, but a potentially much weaker
protocol, and contained a vulnerability permitting arbitrary code
execution (CVE-2007-4995 ). A side channel attack in the integer
multiplication routines is also addressed (CVE-2007-3108 )."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0166"
  );
  # http://security.debian.org/project/extra/dowkd/dowkd.pl.gz.asc
  script_set_attribute(
    attribute:"see_also",
    value:"http://security-cdn.debian.org/project/extra/dowkd/dowkd.pl.gz.asc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2008/dsa-1571"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl package and subsequently regenerate any
cryptographic material, as outlined above.

For the stable distribution (etch), these problems have been fixed in
version 0.9.8c-4etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"4.0", prefix:"libssl-dev", reference:"0.9.8c-4etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8", reference:"0.9.8c-4etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8c-4etch3")) flag++;
if (deb_check(release:"4.0", prefix:"openssl", reference:"0.9.8c-4etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
