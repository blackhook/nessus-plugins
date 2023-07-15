#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2291-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139008);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/30");

  script_cve_id("CVE-2019-13390", "CVE-2019-17542", "CVE-2020-13904");

  script_name(english:"Debian DLA-2291-1 : ffmpeg security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been fixed by upgrading FFmpeg, a widely
used multimedia framework, from 3.2.14 to 3.2.15.

CVE-2019-13390

rawenc: Only accept the appropriate stream type for raw muxers.

CVE-2019-17542

Heap-based buffer overflow in vqa_decode_chunk.

CVE-2020-13904

Use-after-free via a crafted EXTINF duration in an m3u8 file.

For Debian 9 stretch, these problems have been fixed in version
7:3.2.15-0+deb9u1.

Several other bugs are also fixed in 3.2.15, a full list of changes is
available at
https://git.ffmpeg.org/gitweb/ffmpeg.git/blob/37a8ad9a3167923d50091003
1a8086489c004d83:/Changelog

We recommend that you upgrade your ffmpeg packages.

For the detailed security status of ffmpeg please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/ffmpeg

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  # https://git.ffmpeg.org/gitweb/ffmpeg.git/blob/37a8ad9a3167923d500910031a8086489c004d83:/Changelog
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4441a2ab"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ffmpeg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ffmpeg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");
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
if (deb_check(release:"9.0", prefix:"ffmpeg", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ffmpeg-doc", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libav-tools", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec-extra", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec-extra57", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavcodec57", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavdevice-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavdevice57", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter-extra", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter-extra6", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavfilter6", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavformat-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavformat57", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavresample-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavresample3", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavutil-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libavutil55", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpostproc-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpostproc54", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswresample-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswresample2", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswscale-dev", reference:"7:3.2.15-0+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libswscale4", reference:"7:3.2.15-0+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
