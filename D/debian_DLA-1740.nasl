#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1740-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123527);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-1872", "CVE-2017-1000460", "CVE-2017-14058", "CVE-2018-1999012", "CVE-2018-6392");
  script_bugtraq_id(72644);

  script_name(english:"Debian DLA-1740-1 : libav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been corrected in multiple demuxers and
decoders of the libav multimedia library.

CVE-2015-1872

The ff_mjpeg_decode_sof function in libavcodec/mjpegdec.c did not
validate the number of components in a JPEG-LS Start Of Frame segment,
which allowed remote attackers to cause a denial of service
(out-of-bounds array access) or possibly have unspecified other impact
via crafted Motion JPEG data.

CVE-2017-14058

The read_data function in libavformat/hls.c did not restrict reload
attempts for an insufficient list, which allowed remote attackers to
cause a denial of service (infinite loop).

CVE-2017-1000460

In get_last_needed_nal() (libavformat/h264.c) the return value of
init_get_bits was ignored and get_ue_golomb(&gb) was called on an
uninitialized get_bits context, which caused a NULL deref exception.

CVE-2018-6392

The filter_slice function in libavfilter/vf_transpose.c allowed remote
attackers to cause a denial of service (out-of-array access) via a
crafted MP4 file.

CVE-2018-1999012

libav contained a CWE-835: Infinite loop vulnerability in pva format
demuxer that could result in a vulnerability that allowed attackers to
consume excessive amount of resources like CPU and RAM. This attack
appeared to be exploitable via specially crafted PVA file had to be
provided as input.

For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u6.

We recommend that you upgrade your libav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1872");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");
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
if (deb_check(release:"8.0", prefix:"libav-dbg", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libav-doc", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libav-tools", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra-56", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec56", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice55", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter5", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat56", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample2", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil54", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale-dev", reference:"6:11.12-1~deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale3", reference:"6:11.12-1~deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
