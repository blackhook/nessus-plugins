#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1518-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117711);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2013-0169",
    "CVE-2018-0497",
    "CVE-2018-0498",
    "CVE-2018-9988",
    "CVE-2018-9989"
  );
  script_bugtraq_id(57778);
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Debian DLA-1518-1 : polarssl security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Two vulnerabilities were discovered in polarssl, a lightweight crypto
and SSL/TLS library (nowadays continued under the name mbedtls) which
could result in plain text recovery via side-channel attacks.

Two other minor vulnerabilities were discovered in polarssl which
could result in arithmetic overflow errors.

CVE-2018-0497

As a protection against the Lucky Thirteen attack, the TLS code for
CBC decryption in encrypt-then-MAC mode performs extra MAC
calculations to compensate for variations in message size due to
padding. The amount of extra MAC calculation to perform was based on
the assumption that the bulk of the time is spent in processing
64-byte blocks, which is correct for most supported hashes but not for
SHA-384. Correct the amount of extra work for SHA-384 (and SHA-512
which is currently not used in TLS, and MD2 although no one should
care about that).

This is a regression fix for what CVE-2013-0169 had been
fixed this.

CVE-2018-0498

The basis for the Lucky 13 family of attacks is for an attacker to be
able to distinguish between (long) valid TLS-CBC padding and invalid
TLS-CBC padding. Since our code sets padlen = 0 for invalid padding,
the length of the input to the HMAC function gives information about
that.

Information about this length (modulo the MD/SHA block size)
can be deduced from how much MD/SHA padding (this is
distinct from TLS-CBC padding) is used. If MD/SHA padding is
read from a (static) buffer, a local attacker could get
information about how much is used via a cache attack
targeting that buffer.

Let's get rid of this buffer. Now the only buffer used is
the internal MD/SHA one, which is always read fully by the
process() function.

CVE-2018-9988

Prevent arithmetic overflow on bounds check and add bound check before
signature length read in ssl_parse_server_key_exchange().

CVE-2018-9989

Prevent arithmetic overflow on bounds check and add bound check before
length read in ssl_parse_server_psk_hint()

For Debian 8 'Jessie', these problems have been fixed in version
1.3.9-2.1+deb8u4.

We recommend that you upgrade your polarssl packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00029.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/polarssl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolarssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolarssl-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpolarssl7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"libpolarssl-dev", reference:"1.3.9-2.1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolarssl-runtime", reference:"1.3.9-2.1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libpolarssl7", reference:"1.3.9-2.1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
