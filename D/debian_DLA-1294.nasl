#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1294-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106985);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-7187");

  script_name(english:"Debian DLA-1294-1 : golang security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was an arbitrary command execution
vulnerability in the Go programming language.

The 'go get' implementation did not correctly validate 'import path'
statements for '://' which allowed remote attackers to execute
arbitrary OS commands via a crafted website.

For Debian 7 'Wheezy', this issue has been fixed in golang version
2:1.0.2-1.1+deb7u3.

We recommend that you upgrade your golang packages. The Debian LTS
team would like to thank Abhijith PA for preparing this update.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/02/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/golang"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kate-syntax-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vim-syntax-go");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/26");
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
if (deb_check(release:"7.0", prefix:"golang", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"golang-dbg", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"golang-doc", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"golang-go", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"golang-mode", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"golang-src", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"kate-syntax-go", reference:"2:1.0.2-1.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"vim-syntax-go", reference:"2:1.0.2-1.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
