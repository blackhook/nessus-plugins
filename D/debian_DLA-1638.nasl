#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1638-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121315);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-3616", "CVE-2018-11212", "CVE-2018-11213", "CVE-2018-11214", "CVE-2018-1152");
  script_xref(name:"TRA", value:"TRA-2018-17");

  script_name(english:"Debian DLA-1638-1 : libjpeg-turbo security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been resolved in libjpeg-turbo, Debian's
default JPEG implemenation.

CVE-2016-3616

The cjpeg utility in libjpeg allowed remote attackers to cause a
denial of service (NULL pointer dereference and application crash) or
execute arbitrary code via a crafted file.

This issue got fixed by the same patch that fixed
CVE-2018-11213 and CVE-2018-11214.

CVE-2018-1152

libjpeg-turbo has been found vulnerable to a denial of service
vulnerability caused by a divide by zero when processing a crafted BMP
image. The issue has been resolved by a boundary check.

CVE-2018-11212

The alloc_sarray function in jmemmgr.c allowed remote attackers to
cause a denial of service (divide-by-zero error) via a crafted file.

The issue has been addressed by checking the image size when
reading a targa file and throwing an error when image width
or height is 0.

CVE-2018-11213 CVE-2018-11214

The get_text_gray_row and get_text_rgb_row functions in rdppm.c both
allowed remote attackers to cause a denial of service (Segmentation
fault) via a crafted file.

By checking the range of integer values in PPM text files
and adding checks to ensure values are within the specified
range, both issues

For Debian 8 'Jessie', these problems have been fixed in version
1:1.3.1-12+deb8u1.

We recommend that you upgrade your libjpeg-turbo packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/01/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libjpeg-turbo"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2018-17"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-turbo-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg-turbo-progs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjpeg62-turbo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libturbojpeg1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/23");
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
if (deb_check(release:"8.0", prefix:"libjpeg-dev", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjpeg-turbo-progs", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjpeg-turbo-progs-dbg", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjpeg62-turbo", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjpeg62-turbo-dbg", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libjpeg62-turbo-dev", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libturbojpeg1", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libturbojpeg1-dbg", reference:"1:1.3.1-12+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libturbojpeg1-dev", reference:"1:1.3.1-12+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
