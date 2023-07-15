#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1595-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119123);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492");

  script_name(english:"Debian DLA-1595-1 : gnuplot5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gnuplot5, a command-line driven interactive plotting program, has been
examined with fuzzing by Tim Blazytko, Cornelius Aschermann, Sergej
Schumilo and Nils Bars. They found various overflow cases which might
lead to the execution of arbitrary code.

Due to special toolchain hardening in Debian, CVE-2018-19492 is not
security relevant, but it is a bug and the patch was applied for the
sake of completeness. Probably some downstream project does not have
the same toolchain settings.

For Debian 8 'Jessie', these problems have been fixed in version
5.0.0~rc+dfsg2-1+deb8u1.

We recommend that you upgrade your gnuplot5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/gnuplot5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuplot5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuplot5-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuplot5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuplot5-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuplot5-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnuplot5-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/26");
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
if (deb_check(release:"8.0", prefix:"gnuplot5", reference:"5.0.0~rc+dfsg2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gnuplot5-data", reference:"5.0.0~rc+dfsg2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gnuplot5-doc", reference:"5.0.0~rc+dfsg2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gnuplot5-nox", reference:"5.0.0~rc+dfsg2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gnuplot5-qt", reference:"5.0.0~rc+dfsg2-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gnuplot5-x11", reference:"5.0.0~rc+dfsg2-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
