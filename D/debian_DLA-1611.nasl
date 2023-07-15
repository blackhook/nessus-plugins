#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1611-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119816);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-6822", "CVE-2015-6823", "CVE-2015-6824");

  script_name(english:"Debian DLA-1611-2 : libav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two more security issues have been corrected in the libav multimedia
library. This is a follow-up announcement for DLA-1611-1.

CVE-2015-6823

The allocate_buffers function in libavcodec/alac.c did not initialize
certain context data, which allowed remote attackers to cause a denial
of service (segmentation violation) or possibly have unspecified other
impact via crafted Apple Lossless Audio Codec (ALAC) data. This issues
has now been addressed by clearing pointers in avcodec/alac.c's
allocate_buffers().

Other than stated in debian/changelog of upload
6:11.12-1~deb8u2, this issue only now got fixed with upload
of 6:11.12-1~deb8u3.

CVE-2015-6824

The sws_init_context function in libswscale/utils.c did not initialize
certain pixbuf data structures, which allowed remote attackers to
cause a denial of service (segmentation violation) or possibly have
unspecified other impact via crafted video data. In swscale/utils.c
now these pix buffers get cleared which fixes use of uninitialized
memory.

Other than stated in debian/changelog of upload
6:11.12-1~deb8u2, this issue only now got fixed with upload
of 6:11.12-1~deb8u3.

For Debian 8 'Jessie', these problems have been fixed in version
6:11.12-1~deb8u3.

We recommend that you upgrade your libav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");
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
if (deb_check(release:"8.0", prefix:"libav-dbg", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libav-doc", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libav-tools", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec-extra-56", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavcodec56", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavdevice55", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavfilter5", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavformat56", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavresample2", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libavutil54", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale-dev", reference:"6:11.12-1~deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libswscale3", reference:"6:11.12-1~deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
