#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2577-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146893);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/03");

  script_cve_id("CVE-2017-1000433", "CVE-2021-21239");

  script_name(english:"Debian DLA-2577-1 : python-pysaml2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several issues have been found in python-pysaml2, a pure python
implementation of SAML Version 2 Standard.

CVE-2017-1000433

pysaml2 accept any password when run with python optimizations
enabled. This allows attackers to log in as any user without knowing
their password.

CVE-2021-21239

pysaml2 has an improper verification of cryptographic signature
vulnerability. Users of pysaml2 that use the default
CryptoBackendXmlSec1 backend and need to verify signed SAML documents
are impacted. PySAML2 does not ensure that a signed SAML document is
correctly signed. The default CryptoBackendXmlSec1 backend is using
the xmlsec1 binary to verify the signature of signed SAML documents,
but by default xmlsec1 accepts any type of key found within the given
document. xmlsec1 needs to be configured explicitly to only use only
_x509 certificates_ for the verification process of the SAML document
signature.

For Debian 9 stretch, these problems have been fixed in version
3.0.0-5+deb9u2.

We recommend that you upgrade your python-pysaml2 packages.

For the detailed security status of python-pysaml2 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/python-pysaml2

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/python-pysaml2"
  );
  # https://security-tracker.debian.org/tracker/source-package/python-pysaml2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?757b3296"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pysaml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pysaml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-pysaml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"python-pysaml2", reference:"3.0.0-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-pysaml2-doc", reference:"3.0.0-5+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python3-pysaml2", reference:"3.0.0-5+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
