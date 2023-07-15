#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1081-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102889);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-10928", "CVE-2017-10995", "CVE-2017-11141", "CVE-2017-11170", "CVE-2017-11188", "CVE-2017-11352", "CVE-2017-11360", "CVE-2017-11446", "CVE-2017-11448", "CVE-2017-11449", "CVE-2017-11450", "CVE-2017-11478", "CVE-2017-11505", "CVE-2017-11523", "CVE-2017-11524", "CVE-2017-11525", "CVE-2017-11526", "CVE-2017-11527", "CVE-2017-11528", "CVE-2017-11529", "CVE-2017-11530", "CVE-2017-11531", "CVE-2017-11532", "CVE-2017-11533", "CVE-2017-11534", "CVE-2017-11535", "CVE-2017-11537", "CVE-2017-11539", "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-11751", "CVE-2017-11752", "CVE-2017-12140", "CVE-2017-12418", "CVE-2017-12427", "CVE-2017-12428", "CVE-2017-12429", "CVE-2017-12430", "CVE-2017-12431", "CVE-2017-12432", "CVE-2017-12433", "CVE-2017-12435", "CVE-2017-12563", "CVE-2017-12564", "CVE-2017-12565", "CVE-2017-12566", "CVE-2017-12587", "CVE-2017-12640", "CVE-2017-12641", "CVE-2017-12642", "CVE-2017-12643", "CVE-2017-12654", "CVE-2017-12664", "CVE-2017-12665", "CVE-2017-12668", "CVE-2017-12670", "CVE-2017-12674", "CVE-2017-12675", "CVE-2017-12676", "CVE-2017-12877", "CVE-2017-12983", "CVE-2017-13133", "CVE-2017-13134", "CVE-2017-13139", "CVE-2017-13142", "CVE-2017-13143", "CVE-2017-13144", "CVE-2017-13146", "CVE-2017-13658", "CVE-2017-8352", "CVE-2017-9144", "CVE-2017-9501");

  script_name(english:"Debian DLA-1081-1 : imagemagick security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates fixes numerous vulnerabilities in imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service, memory disclosure or the
execution of arbitrary code if malformed DPX, RLE, CIN, DIB, EPT, MAT,
VST, PNG, JNG, MNG, DVJU, JPEG, TXT, PES, MPC, UIL, PS, PALM, CIP,
TIFF, ICON, MAGICK, DCM, MSL, WMF, MIFF, PCX, SUN, PSD, MVG, PWP,
PICT, PDB, SFW, or XCF files are processed.

For Debian 7 'Wheezy', these problems have been fixed in version
6.7.7.10-5+deb7u16.

We recommend that you upgrade your imagemagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"7.0", prefix:"imagemagick", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-common", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-dbg", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-doc", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++-dev", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++5", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore-dev", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5-extra", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand-dev", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand5", reference:"6.7.7.10-5+deb7u16")) flag++;
if (deb_check(release:"7.0", prefix:"perlmagick", reference:"6.7.7.10-5+deb7u16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
