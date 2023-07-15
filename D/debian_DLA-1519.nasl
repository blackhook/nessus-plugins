#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1519-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117712);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000158", "CVE-2018-1000802", "CVE-2018-1060", "CVE-2018-1061");

  script_name(english:"Debian DLA-1519-1 : python2.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in the CPython interpreter which
can cause denial of service, information gain, and arbitrary code
execution.

CVE-2017-1000158

CPython (aka Python) is vulnerable to an integer overflow in the
PyString_DecodeEscape function in stringobject.c, resulting in
heap-based buffer overflow (and possible arbitrary code execution)

CVE-2018-1060

python is vulnerable to catastrophic backtracking in pop3lib's apop()
method. An attacker could use this flaw to cause denial of service.

CVE-2018-1061

python is vulnerable to catastrophic backtracking in the
difflib.IS_LINE_JUNK method. An attacker could use this flaw to cause
denial of service.

CVE-2018-1000802

Python Software Foundation Python (CPython) version 2.7 contains a
CWE-77: Improper Neutralization of Special Elements used in a Command
('Command Injection') vulnerability in shutil module (make_archive
function) that can result in Denial of service, Information gain via
injection of arbitrary files on the system or entire drive. This
attack appear to be exploitable via Passage of unfiltered user input
to the function.

For Debian 8 'Jessie', these problems have been fixed in version
2.7.9-2+deb8u2.

We recommend that you upgrade your python2.7 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/python2.7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");
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
if (deb_check(release:"8.0", prefix:"idle-python2.7", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-dbg", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-dev", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-minimal", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-stdlib", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpython2.7-testsuite", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-dbg", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-dev", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-doc", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-examples", reference:"2.7.9-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python2.7-minimal", reference:"2.7.9-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
