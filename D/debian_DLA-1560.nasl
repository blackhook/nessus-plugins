#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1560-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118504);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-10844", "CVE-2018-10845", "CVE-2018-10846");

  script_name(english:"Debian DLA-1560-1 : gnutls28 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A set of vulnerabilities was discovered in GnuTLS which allowed
attackers to do plain text recovery on TLS connections with certain
cipher types.

CVE-2018-10844

It was found that the GnuTLS implementation of HMAC-SHA-256 was
vulnerable to a Lucky thirteen style attack. Remote attackers could
use this flaw to conduct distinguishing attacks and plaintext-recovery
attacks via statistical analysis of timing data using crafted packets.

CVE-2018-10845

It was found that the GnuTLS implementation of HMAC-SHA-384 was
vulnerable to a Lucky thirteen style attack. Remote attackers could
use this flaw to conduct distinguishing attacks and plain text
recovery attacks via statistical analysis of timing data using crafted
packets.

CVE-2018-10846

A cache-based side channel in GnuTLS implementation that leads to
plain text recovery in cross-VM attack setting was found. An attacker
could use a combination of 'Just in Time' Prime+probe attack in
combination with Lucky-13 attack to recover plain text using crafted
packets.

For Debian 8 'Jessie', these problems have been fixed in version
3.3.30-0+deb8u1. It was found to be more practical to update to the
latest upstream version of the 3.3.x branch since upstream's fixes
were rather invasive and required cipher list changes anyways. This
will facilitate future LTS updates as well.

This change therefore also includes the following major policy
changes, as documented in the NEWS file :

  - ARCFOUR (RC4) and SSL 3.0 are no longer included in the
    default priorities list. Those have to be explicitly
    enabled, e.g., with a string like 'NORMAL:+ARCFOUR-128'
    or 'NORMAL:+VERS-SSL3.0', respectively.

  - The ciphers utilizing HMAC-SHA384 and SHA256 have been
    removed from the default priority strings. They are not
    necessary for compatibility or other purpose and provide
    no advantage over their SHA1 counter-parts, as they all
    depend on the legacy TLS CBC block mode.

  - Follow closely RFC5280 recommendations and use UTCTime
    for dates prior to 2050.

  - Require strict DER encoding for certificates, OCSP
    requests, private keys, CRLs and certificate requests,
    in order to reduce issues due to the complexity of BER
    rules.

  - Refuse to import v1 or v2 certificates that contain
    extensions.

API and ABI compatibility is retained, however, although new symbols
have been added. Many bugfixes are also included in the upload. See
the provided upstream changelog for more details.

We recommend that you upgrade your gnutls28 packages and do not expect
significant breakage.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gnutls28"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:guile-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls-deb0-28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls-openssl27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls28-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutls28-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"gnutls-bin", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gnutls-doc", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"guile-gnutls", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls-deb0-28", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls-openssl27", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls28-dbg", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutls28-dev", reference:"3.3.30-0+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgnutlsxx28", reference:"3.3.30-0+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
