#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3957. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102807);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-11399", "CVE-2017-11665", "CVE-2017-11719", "CVE-2017-9608", "CVE-2017-9993");
  script_xref(name:"DSA", value:"3957");

  script_name(english:"Debian DSA-3957-1 : ffmpeg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in FFmpeg, a multimedia
player, server and encoder. These issues could lead to
Denial-of-Service and, in some situation, the execution of arbitrary
code.

  - CVE-2017-9608
    Yihan Lian of Qihoo 360 GearTeam discovered a NULL
    pointer access when parsing a crafted MOV file.

  - CVE-2017-9993
    Thierry Foucu discovered that it was possible to leak
    information from files and symlinks ending in common
    multimedia extensions, using the HTTP Live Streaming.

  - CVE-2017-11399
    Liu Bingchang of IIE discovered an integer overflow in
    the APE decoder that can be triggered by a crafted APE
    file.

  - CVE-2017-11665
    JunDong Xie of Ant-financial Light-Year Security Lab
    discovered that an attacker able to craft a RTMP stream
    can crash FFmpeg.

  - CVE-2017-11719
    Liu Bingchang of IIE discovered an out-of-bound access
    that can be triggered by a crafted DNxHD file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-9993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-11399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-11665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-11719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ffmpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2017/dsa-3957"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ffmpeg packages.

For the stable distribution (stretch), these problems have been fixed
in version 7:3.2.7-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/29");
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
if (deb_check(release:"9.0", prefix:"ffmpeg", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ffmpeg-doc", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libav-tools", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec-extra", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec-extra57", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec57", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavdevice-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavdevice57", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter-extra", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter-extra6", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter6", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavformat-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavformat57", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavresample-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavresample3", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavutil-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavutil55", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpostproc-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpostproc54", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswresample-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswresample2", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswscale-dev", reference:"7:3.2.7-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswscale4", reference:"7:3.2.7-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
