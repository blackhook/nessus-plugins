#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1583-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119100);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-5203", "CVE-2015-5221", "CVE-2016-8690", "CVE-2017-13748", "CVE-2017-14132");

  script_name(english:"Debian DLA-1583-1 : jasper security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in the JasPer
JPEG-2000 library.

CVE-2015-5203

Gustavo Grieco discovered an integer overflow vulnerability that
allows remote attackers to cause a denial of service or may have other
unspecified impact via a crafted JPEG 2000 image file.

CVE-2015-5221

Josselin Feist found a double-free vulnerability that allows remote
attackers to cause a denial of service (application crash) by
processing a malformed image file.

CVE-2016-8690

Gustavo Grieco discovered a NULL pointer dereference vulnerability
that can cause a denial of service via a crafted BMP image file. The
update also includes the fixes for the related issues CVE-2016-8884
and CVE-2016-8885 which complete the patch for CVE-2016-8690.

CVE-2017-13748

It was discovered that jasper does not properly release memory used to
store image tile data when image decoding fails which may lead to a
denial of service.

CVE-2017-14132

A heap-based buffer over-read was found related to the
jas_image_ishomosamp function that could be triggered via a crafted
image file and may cause a denial of service (application crash) or
have other unspecified impact.

For Debian 8 'Jessie', these problems have been fixed in version
1.900.1-debian1-2.4+deb8u4.

We recommend that you upgrade your jasper packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/jasper"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/23");
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
if (deb_check(release:"8.0", prefix:"libjasper-dev", reference:"1.900.1-debian1-2.4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper-runtime", reference:"1.900.1-debian1-2.4+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libjasper1", reference:"1.900.1-debian1-2.4+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
