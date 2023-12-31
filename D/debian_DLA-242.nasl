#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-242-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84130);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-3437", "CVE-2014-8354", "CVE-2014-8355", "CVE-2014-8562");
  script_bugtraq_id(54714, 70830, 70837, 70839);

  script_name(english:"Debian DLA-242-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a large number of potential security problems due to
insufficient data validation when parsing different input formats.
Most of those potential security problems do not have a CVE number
assigned.

While the security implications of all of these problems are not all
fully known, it is highly recommended to update.

The update fixes the following identified vulnerabilities :

CVE-2012-3437

Incorrect validation of PNG buffer size, leading to DoS using
specially crafted PNG files.

CVE-2014-8354

Out of bounds memory access in resize

CVE-2014-8355

Buffer overflow in PCX reader

CVE-2014-8562

Buffer overflow in DCM readers

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/06/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"6.0", prefix:"imagemagick", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-dbg", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"imagemagick-doc", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++-dev", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagick++3", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore-dev", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickcore3-extra", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand-dev", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libmagickwand3", reference:"8:6.6.0.4-3+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"perlmagick", reference:"8:6.6.0.4-3+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
