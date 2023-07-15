#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1630-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(120988);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-14055", "CVE-2017-14056", "CVE-2017-14057", "CVE-2017-14170", "CVE-2017-14171", "CVE-2017-14767", "CVE-2017-15672", "CVE-2017-17130", "CVE-2017-9993", "CVE-2017-9994", "CVE-2018-14394", "CVE-2018-1999010", "CVE-2018-6621", "CVE-2018-7557");

  script_name(english:"Debian DLA-1630-1 : libav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were corrected in the libav
multimedia library which may lead to a denial of service, information
disclosure or the execution of arbitrary code if a malformed file is
processed.

CVE-2017-9993

Libav does not properly restrict HTTP Live Streaming filename
extensions and demuxer names, which allows attackers to read arbitrary
files via crafted playlist data.

CVE-2017-9994

libavcodec/webp.c in Libav does not ensure that pix_fmt is set, which
allows remote attackers to cause a denial of service (heap-based
buffer overflow and application crash) or possibly have unspecified
other impact via a crafted file, related to the
vp8_decode_mb_row_no_filter and pred8x8_128_dc_8_c functions.

CVE-2017-14055

denial of service in mv_read_header() due to lack of an EOF (End of
File) check might cause huge CPU and memory consumption.

CVE-2017-14056

denial of service in rl2_read_header() due to lack of an EOF (End of
File) check might cause huge CPU and memory consumption.

CVE-2017-14057

denial of service in asf_read_marker() due to lack of an EOF (End of
File) check might cause huge CPU and memory consumption.

CVE-2017-14170

denial of service in mxf_read_index_entry_array() due to lack of an
EOF (End of File) check might cause huge CPU consumption.

CVE-2017-14171

denial of service in nsv_parse_NSVf_header() due to lack of an EOF
(End of File) check might cause huge CPU consumption.

CVE-2017-14767

The sdp_parse_fmtp_config_h264 function in libavformat/rtpdec_h264.c
mishandles empty sprop-parameter-sets values, which allows remote
attackers to cause a denial of service (heap buffer overflow) or
possibly have unspecified other impact via a crafted sdp file.

CVE-2017-15672

The read_header function in libavcodec/ffv1dec.c allows remote
attackers to have unspecified impact via a crafted MP4 file, which
triggers an out-of-bounds read.

CVE-2017-17130

The ff_free_picture_tables function in libavcodec/mpegpicture.c allows
remote attackers to cause a denial of service (heap-based buffer
overflow and application crash) or possibly have unspecified other
impact via a crafted file, related to vc1_decode_i_blocks_adv.

CVE-2018-6621

The decode_frame function in libavcodec/utvideodec.c in Libav allows
remote attackers to cause a denial of service (out of array read) via
a crafted AVI file.

CVE-2018-7557

The decode_init function in libavcodec/utvideodec.c in Libav allows
remote attackers to cause a denial of service (Out of array read) via
an AVI file with crafted dimensions within chroma subsampling data.

CVE-2018-14394

libavformat/movenc.c in Libav allows attackers to cause a denial of
service (application crash caused by a divide-by-zero error) with a
user crafted Waveform audio file.

CVE-2018-1999010

Libav contains multiple out of array access vulnerabilities in the mms
protocol that can result in attackers accessing out of bound data.

For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u4.

We recommend that you upgrade your libav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00006.html"
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");
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
if (deb_check(release:"8.0", prefix:"libav-dbg", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libav-doc", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libav-tools", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra-56", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec56", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice55", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter5", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat56", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample2", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil54", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale-dev", reference:"6:11.12-1~deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale3", reference:"6:11.12-1~deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
