#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1438-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111223);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-1516", "CVE-2017-1000450", "CVE-2017-12597", "CVE-2017-12598", "CVE-2017-12599", "CVE-2017-12601", "CVE-2017-12603", "CVE-2017-12604", "CVE-2017-12605", "CVE-2017-12606", "CVE-2017-12862", "CVE-2017-12863", "CVE-2017-12864", "CVE-2017-14136", "CVE-2017-17760", "CVE-2018-5268", "CVE-2018-5269");

  script_name(english:"Debian DLA-1438-1 : opencv security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Early versions of opencv have problems while reading data, which might
result in either buffer overflows, out-of bounds errors or integer
overflows.

Further assertion errors might happen due to incorrect integer cast.

For Debian 8 'Jessie', these problems have been fixed in version
2.4.9.1+dfsg-1+deb8u2.

We recommend that you upgrade your opencv packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/opencv"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcv2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcvaux-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcvaux2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhighgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhighgui2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-calib3d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-calib3d2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-contrib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-contrib2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-core2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-features2d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-features2d2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-flann-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-flann2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-gpu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-gpu2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-highgui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-highgui2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-imgproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-imgproc2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-legacy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-legacy2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ml-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ml2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-objdetect-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-objdetect2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ocl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ocl2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-photo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-photo2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-stitching-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-stitching2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-superres-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-superres2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ts-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-ts2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-video-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-video2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-videostab-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv-videostab2.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopencv2.4-jni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opencv-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opencv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-opencv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/23");
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
if (deb_check(release:"8.0", prefix:"libcv-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libcv2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libcvaux-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libcvaux2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libhighgui-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libhighgui2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-calib3d-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-calib3d2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-contrib-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-contrib2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-core-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-core2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-features2d-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-features2d2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-flann-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-flann2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-gpu-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-gpu2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-highgui-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-highgui2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-imgproc-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-imgproc2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-legacy-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-legacy2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-ml-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-ml2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-objdetect-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-objdetect2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-ocl-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-ocl2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-photo-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-photo2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-stitching-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-stitching2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-superres-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-superres2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-ts-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-ts2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-video-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-video2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-videostab-dev", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv-videostab2.4", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv2.4-java", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libopencv2.4-jni", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"opencv-data", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"opencv-doc", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-opencv", reference:"2.4.9.1+dfsg-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
