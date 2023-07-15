#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2021-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131740);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-17127", "CVE-2017-18245", "CVE-2018-19128", "CVE-2018-19130", "CVE-2019-14443", "CVE-2019-17542");

  script_name(english:"Debian DLA-2021-1 : libav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues were fixed in libav, a multimedia library for
processing audio and video files.

CVE-2017-17127

The vc1_decode_frame function in libavcodec/vc1dec.c allows remote
attackers to cause a denial of service (NULL pointer dereference and
application crash) via a crafted file. CVE-2018-19130 is a duplicate
of this vulnerability.

CVE-2017-18245

The mpc8_probe function in libavformat/mpc8.c allows remote attackers
to cause a denial of service (heap-based buffer over-read) via a
crafted audio file on 32-bit systems.

CVE-2018-19128

Heap-based buffer over-read in decode_frame in libavcodec/lcldec.c
allows an attacker to cause denial of service via a crafted avi file.

CVE-2019-14443

Division by zero in range_decode_culshift in libavcodec/apedec.c
allows remote attackers to cause a denial of service (application
crash), as demonstrated by avconv.

CVE-2019-17542

Heap-based buffer overflow in vqa_decode_chunk because of an
out-of-array access in vqa_decode_init in libavcodec/vqavideo.c.

For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u9.

We recommend that you upgrade your libav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra-56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/06");
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
if (deb_check(release:"8.0", prefix:"libav-dbg", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libav-doc", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libav-tools", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra-56", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec56", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice55", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter5", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat56", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample2", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil54", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale-dev", reference:"6:11.12-1~deb8u9")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale3", reference:"6:11.12-1~deb8u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
