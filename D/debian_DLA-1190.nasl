#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1190-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104749);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000158");

  script_name(english:"Debian DLA-1190-1 : python2.6 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A minor security vulnerability has been discovered in Python 2.7, an
interactive high-level object-oriented language.

CVE-2017-1000158

CPython (the reference implementation of Python also commonly known as
simply Python) versions 2.6 and 2.7 are vulnerable to an integer
overflow and heap corruption, leading to possible arbitrary code
execution. The nature of the error has to do with improper handling of
large strings with escaped characters.

For Debian 7 'Wheezy', these problems have been fixed in version
2.6.8-1.1+deb7u1.

We recommend that you upgrade your python2.6 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/11/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python2.6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.6-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"idle-python2.6", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpython2.6", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python2.6", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python2.6-dbg", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python2.6-dev", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python2.6-doc", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python2.6-examples", reference:"2.6.8-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python2.6-minimal", reference:"2.6.8-1.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
