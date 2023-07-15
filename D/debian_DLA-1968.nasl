#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1968-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130133);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2019-11470", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140");

  script_name(english:"Debian DLA-1968-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in imagemagick, an image
processing toolkit.

CVE-2019-11470

Uncontrolled resource consumption caused by insufficiently sanitized
image size in ReadCINImage (coders/cin.c). This vulnerability might be
leveraged by remote attackers to cause denial of service via a crafted
Cineon image.

CVE-2019-14981

Divide-by-zero vulnerability in MeanShiftImage (magick/feature.c).
This vulnerability might be leveraged by remote attackers to cause
denial of service via crafted image data.

CVE-2019-15139

Out-of-bounds read in ReadXWDImage (coders/xwd.c). This vulnerability
might be leveraged by remote attackers to cause denial of service via
a crafted XWD (X Window System window dumping file) image file.

CVE-2019-15140

Bound checking issue in ReadMATImage (coders/mat.c), potentially
leading to use-after-free. This vulnerability might be leveraged by
remote attackers to cause denial of service or any other unspecified
impact via a crafted MAT image file.

For Debian 8 'Jessie', these problems have been fixed in version
8:6.8.9.9-5+deb8u18.

We recommend that you upgrade your imagemagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/10/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15140");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-6.q16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libimage-magick-q16-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-arch-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-6.q16-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"imagemagick", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-6.q16", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-common", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-dbg", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-doc", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-perl", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-q16-perl", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6-headers", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-5", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-dev", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-headers", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2-extra", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-dev", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6-headers", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-2", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-dev", reference:"8:6.8.9.9-5+deb8u18")) flag++;
if (deb_check(release:"8.0", prefix:"perlmagick", reference:"8:6.8.9.9-5+deb8u18")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
