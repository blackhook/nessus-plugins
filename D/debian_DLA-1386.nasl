#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1386-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110162);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-7866", "CVE-2018-7873", "CVE-2018-7876", "CVE-2018-9009", "CVE-2018-9132");

  script_name(english:"Debian DLA-1386-1 : ming security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in Ming :

CVE-2018-7866

NULL pointer dereference in the newVar3 function (util/decompile.c).
Remote attackers might leverage this vulnerability to cause a denial
of service via a crafted swf file.

CVE-2018-7873

Heap-based buffer overflow vulnerability in the getString function
(util/decompile.c). Remote attackers might leverage this vulnerability
to cause a denial of service via a crafted swf file.

CVE-2018-7876

Integer overflow and resulting memory exhaustion in the
parseSWF_ACTIONRECORD function (util/parser.c). Remote attackers might
leverage this vulnerability to cause a denial of service via a crafted
swf file.

CVE-2018-9009

Various heap-based buffer overflow vulnerabilites in
util/decompiler.c. Remote attackers might leverage this vulnerability
to cause a denial of service via a crafted swf file.

CVE-2018-9132

NULL pointer dereference in the getInt function (util/decompile.c).
Remote attackers might leverage this vulnerability to cause a denial
of service via a crafted swf file.

For Debian 7 'Wheezy', these problems have been fixed in version
1:0.4.4-1.1+deb7u9.

We recommend that you upgrade your ming packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/05/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ming"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libming-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libming-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libming1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswf-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ming-fonts-dejavu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ming-fonts-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-ming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ming");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/29");
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
if (deb_check(release:"7.0", prefix:"libming-dev", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libming-util", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libming1", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libswf-perl", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"ming-fonts-dejavu", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"ming-fonts-opensymbol", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"php5-ming", reference:"1:0.4.4-1.1+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"python-ming", reference:"1:0.4.4-1.1+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
