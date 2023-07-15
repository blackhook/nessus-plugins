#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2366-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140297);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2017-1000445", "CVE-2017-1000476", "CVE-2017-12140", "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12643", "CVE-2017-12670", "CVE-2017-12674", "CVE-2017-12691", "CVE-2017-12692", "CVE-2017-12693", "CVE-2017-12806", "CVE-2017-12875", "CVE-2017-13061", "CVE-2017-13133", "CVE-2017-13658", "CVE-2017-13768", "CVE-2017-14060", "CVE-2017-14172", "CVE-2017-14173", "CVE-2017-14174", "CVE-2017-14175", "CVE-2017-14249", "CVE-2017-14341", "CVE-2017-14400", "CVE-2017-14505", "CVE-2017-14532", "CVE-2017-14624", "CVE-2017-14625", "CVE-2017-14626", "CVE-2017-14739", "CVE-2017-14741", "CVE-2017-15015", "CVE-2017-15017", "CVE-2017-15281", "CVE-2017-17682", "CVE-2017-17914", "CVE-2017-18209", "CVE-2017-18211", "CVE-2017-18271", "CVE-2017-18273", "CVE-2018-16643", "CVE-2018-16749", "CVE-2018-18025", "CVE-2019-11598", "CVE-2019-13135", "CVE-2019-13308", "CVE-2019-13391", "CVE-2019-15139");

  script_name(english:"Debian DLA-2366-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Debian Bug : 870020 870019 876105 869727 886281 873059 870504 870530
870107 872609 875338 875339 875341 873871 873131 875352 878506 875503
875502 876105 876099 878546 878545 877354 877355 878524 878547 878548
878555 878554 878548 878555 878554 878579 885942 886584 928206 941670
931447 932079

Several security vulnerabilities were found in Imagemagick. Various
memory handling problems and cases of missing or incomplete input
sanitizing may result in denial of service, memory or CPU exhaustion,
information disclosure or potentially the execution of arbitrary code
when a malformed image file is processed.

For Debian 9 stretch, these problems have been fixed in version
8:6.9.7.4+dfsg-11+deb9u10.

We recommend that you upgrade your imagemagick packages.

For the detailed security status of imagemagick please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/imagemagick

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18211");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16hdri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16hdri-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16hdri-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"imagemagick", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6-common", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6-doc", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6.q16", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-6.q16hdri", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-common", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"imagemagick-doc", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-perl", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-q16-perl", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libimage-magick-q16hdri-perl", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16-7", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16hdri-7", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagick++-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-3", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-3-extra", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-3", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-3-extra", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickcore-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6-headers", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16-3", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16hdri-3", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-6.q16hdri-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libmagickwand-dev", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"perlmagick", reference:"8:6.9.7.4+dfsg-11+deb9u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
