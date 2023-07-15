#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1456-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111520);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-5239", "CVE-2017-11102", "CVE-2017-11140", "CVE-2017-11403", "CVE-2017-11637", "CVE-2017-11638", "CVE-2017-11641", "CVE-2017-11642", "CVE-2017-12935", "CVE-2017-12936", "CVE-2017-13737", "CVE-2017-13775", "CVE-2017-13776", "CVE-2017-13777", "CVE-2017-14504", "CVE-2017-14994", "CVE-2017-14997", "CVE-2017-15277", "CVE-2017-15930", "CVE-2017-16352", "CVE-2017-16545", "CVE-2017-16547", "CVE-2017-18219", "CVE-2017-18220", "CVE-2017-18229", "CVE-2017-18230", "CVE-2017-18231", "CVE-2017-6335", "CVE-2017-9098", "CVE-2018-5685", "CVE-2018-6799", "CVE-2018-9018");

  script_name(english:"Debian DLA-1456-1 : graphicsmagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various vulnerabilities were discovered in graphicsmagick, a
collection of image processing tools and associated libraries,
resulting in denial of service, information disclosure, and a variety
of buffer overflows and overreads.

For Debian 8 'Jessie', these problems have been fixed in version
1.3.20-3+deb8u4.

We recommend that you upgrade your graphicsmagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/graphicsmagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/03");
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
if (deb_check(release:"8.0", prefix:"graphicsmagick", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-dbg", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphics-magick-perl", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick++3", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.20-3+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libgraphicsmagick3", reference:"1.3.20-3+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
