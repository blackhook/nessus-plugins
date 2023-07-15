#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1283-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106819);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_name(english:"Debian DLA-1283-2 : python-crypto security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to DLA-1283-1. In DLA-1283-1 it is claimed that the
issue described in CVE-2018-6594 is fixed. It turns out that the fix
is partial and upstream has decided not to fix the issue as it would
break compatibility and that ElGamal encryption was not intended to
work on its own.

The recommendation is still to upgrade python-crypto packages. In
addition please take into account that the fix is not complete. If you
have an application using python-crypto is implementing ElGamal
encryption you should consider changing to some other encryption
method.

There will be no further update to python-crypto for this specific
CVE. A fix would break compatibility, the problem has been ignored by
regular Debian Security team due to its minor nature and in addition
to that we are close to the end of life of the Wheezy security
support.

CVE-2018-6594 :

python-crypto generated weak ElGamal key parameters, which allowed
attackers to obtain sensitive information by reading ciphertext data
(i.e., it did not have semantic security in face of a ciphertext-only
attack).

We recommend that you upgrade your python-crypto packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/04/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-crypto"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-crypto-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"python-crypto", reference:"2.6-4+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto-dbg", reference:"2.6-4+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto-doc", reference:"2.6-4+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"python3-crypto", reference:"2.6-4+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"python3-crypto-dbg", reference:"2.6-4+deb7u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
