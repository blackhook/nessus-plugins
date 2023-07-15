#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1411-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110840);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-11613", "CVE-2018-10963", "CVE-2018-5784", "CVE-2018-7456", "CVE-2018-8905");

  script_name(english:"Debian DLA-1411-1 : tiff security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several issues were discovered in TIFF, the Tag Image File Format
library, that allowed remote attackers to cause a denial of service or
other unspecified impact via a crafted image file.

CVE-2017-11613: DoS vulnerability A crafted input will lead to a
denial of service attack. During the TIFFOpen process, td_imagelength
is not checked. The value of td_imagelength can be directly controlled
by an input file. In the ChopUpSingleUncompressedStrip function, the
_TIFFCheckMalloc function is called based on td_imagelength. If the
value of td_imagelength is set close to the amount of system memory,
it will hang the system or trigger the OOM killer.

CVE-2018-10963: DoS vulnerability The TIFFWriteDirectorySec() function
in tif_dirwrite.c in LibTIFF allows remote attackers to cause a denial
of service (assertion failure and application crash) via a crafted
file, a different vulnerability than CVE-2017-13726.

CVE-2018-5784: DoS vulnerability In LibTIFF, there is an uncontrolled
resource consumption in the TIFFSetDirectory function of tif_dir.c.
Remote attackers could leverage this vulnerability to cause a denial
of service via a crafted tif file. This occurs because the declared
number of directory entries is not validated against the actual number
of directory entries.

CVE-2018-7456: NULL pointer Dereference A NULL pointer Dereference
occurs in the function TIFFPrintDirectory in tif_print.c in LibTIFF
when using the tiffinfo tool to print crafted TIFF information, a
different vulnerability than CVE-2017-18013. (This affects an earlier
part of the TIFFPrintDirectory function that was not addressed by the
CVE-2017-18013 patch.)

CVE-2018-8905: Heap-based buffer overflow In LibTIFF, a heap-based
buffer overflow occurs in the function LZWDecodeCompat in tif_lzw.c
via a crafted TIFF file, as demonstrated by tiff2ps.

For Debian 8 'Jessie', these problems have been fixed in version
4.0.3-12.3+deb8u6.

We recommend that you upgrade your tiff packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/tiff"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/03");
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
if (deb_check(release:"8.0", prefix:"libtiff-doc", reference:"4.0.3-12.3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff-opengl", reference:"4.0.3-12.3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff-tools", reference:"4.0.3-12.3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff5", reference:"4.0.3-12.3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff5-dev", reference:"4.0.3-12.3+deb8u6")) flag++;
if (deb_check(release:"8.0", prefix:"libtiffxx5", reference:"4.0.3-12.3+deb8u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
