#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1228-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105518);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000456");

  script_name(english:"Debian DLA-1228-1 : poppler security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jason Crain discovered a overflow vulnerability in the poppler PDF
rendering library.

For Debian 7 'Wheezy', this issue has been fixed in poppler version
0.18.4-6+deb7u5.

We recommend that you upgrade your poppler packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/poppler"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-poppler-0.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-cpp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-glib8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-private-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler-qt4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpoppler19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");
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
if (deb_check(release:"7.0", prefix:"gir1.2-poppler-0.18", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-cpp-dev", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-cpp0", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-dev", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-glib-dev", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-glib8", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-private-dev", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-qt4-3", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler-qt4-dev", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libpoppler19", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"poppler-dbg", reference:"0.18.4-6+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"poppler-utils", reference:"0.18.4-6+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
