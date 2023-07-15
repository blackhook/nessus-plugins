#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1310-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108522);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-18233", "CVE-2017-18234", "CVE-2017-18236", "CVE-2017-18238", "CVE-2018-7728", "CVE-2018-7730");

  script_name(english:"Debian DLA-1310-1 : exempi security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various issues were discovered in exempi, a library to parse XMP
metadata that may cause a denial of service or may have other
unspecified impact via crafted files.

CVE-2017-18233 An Integer overflow in the Chunk class in RIFF.cpp
allows remote attackers to cause a denial of service (infinite loop)
via crafted XMP data in an .avi file.

CVE-2017-18234 An issue was discovered that allows remote attackers to
cause a denial of service (invalid memcpy with resultant
use-after-free) or possibly have unspecified other impact via a .pdf
file containing JPEG data.

CVE-2017-18236 The ASF_Support::ReadHeaderObject function in
ASF_Support.cpp allows remote attackers to cause a denial of service
(infinite loop) via a crafted .asf file.

CVE-2017-18238 The TradQT_Manager::ParseCachedBoxes function in
QuickTime_Support.cpp allows remote attackers to cause a denial of
service (infinite loop) via crafted XMP data in a .qt file.

CVE-2018-7728 TIFF_Handler.cpp mishandles a case of a zero length,
leading to a heap-based buffer over-read in the MD5Update() function
in MD5.cpp.

CVE-2018-7730 A certain case of a 0xffffffff length is mishandled in
PSIR_FileWriter.cpp, leading to a heap-based buffer over-read in the
PSD_MetaHandler::CacheFileData() function.

For Debian 7 'Wheezy', these problems have been fixed in version
2.2.0-1+deb7u1.

We recommend that you upgrade your exempi packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/exempi"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexempi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexempi3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexempi3-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");
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
if (deb_check(release:"7.0", prefix:"libexempi-dev", reference:"2.2.0-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libexempi3", reference:"2.2.0-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libexempi3-dbg", reference:"2.2.0-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
