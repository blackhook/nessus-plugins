#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-960-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100480);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562", "CVE-2014-8716", "CVE-2014-9841", "CVE-2015-8900", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2017-7941", "CVE-2017-7943", "CVE-2017-8343", "CVE-2017-8344", "CVE-2017-8345", "CVE-2017-8346", "CVE-2017-8347", "CVE-2017-8348", "CVE-2017-8349", "CVE-2017-8350", "CVE-2017-8351", "CVE-2017-8352", "CVE-2017-8353", "CVE-2017-8354", "CVE-2017-8355", "CVE-2017-8356", "CVE-2017-8357", "CVE-2017-8765", "CVE-2017-8830", "CVE-2017-9098", "CVE-2017-9141", "CVE-2017-9142", "CVE-2017-9143", "CVE-2017-9144");
  script_bugtraq_id(70830, 70837, 70839, 70992);

  script_name(english:"Debian DLA-960-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several vulnerabilities in imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service, memory disclosure, or the
execution of arbitrary code if malformed PCX, DCM, JPEG, PSD, HDR,
MIFF, PDB, VICAR, SGI, SVG, AAI, MNG, EXR, MAT, SFW, JNG, PCD, XWD,
PICT, BMP, MTV, SUN, EPT, ICON, DDS, or ART files are processed.

For Debian 7 'Wheezy', these problems have been fixed in version
6.7.7.10-5+deb7u14.

We recommend that you upgrade your imagemagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"7.0", prefix:"imagemagick", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-common", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-dbg", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-doc", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++-dev", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++5", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore-dev", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5-extra", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand-dev", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand5", reference:"6.7.7.10-5+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"perlmagick", reference:"6.7.7.10-5+deb7u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
