#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3652. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93115);
  script_version("2.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-9907", "CVE-2015-8957", "CVE-2015-8958", "CVE-2015-8959", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5010", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842", "CVE-2016-6491", "CVE-2016-6823", "CVE-2016-7513", "CVE-2016-7514", "CVE-2016-7515", "CVE-2016-7516", "CVE-2016-7517", "CVE-2016-7518", "CVE-2016-7519", "CVE-2016-7520", "CVE-2016-7521", "CVE-2016-7522", "CVE-2016-7523", "CVE-2016-7524", "CVE-2016-7525", "CVE-2016-7526", "CVE-2016-7527", "CVE-2016-7528", "CVE-2016-7529", "CVE-2016-7530", "CVE-2016-7531", "CVE-2016-7532", "CVE-2016-7533", "CVE-2016-7534", "CVE-2016-7535", "CVE-2016-7536", "CVE-2016-7537", "CVE-2016-7538", "CVE-2016-7539", "CVE-2016-7540");
  script_xref(name:"DSA", value:"3652");

  script_name(english:"Debian DSA-3652-1 : imagemagick - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This updates fixes many vulnerabilities in imagemagick: Various memory
handling problems and cases of missing or incomplete input sanitising
may result in denial of service or the execution of arbitrary code if
malformed TIFF, WPG, RLE, RAW, PSD, Sun, PICT, VIFF, HDR, Meta,
Quantum, PDB, DDS, DCM, EXIF, RGF or BMP files are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=833003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2016/dsa-3652"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the stable distribution (jessie), these problems have been fixed
in version 8:6.8.9.9-5+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"imagemagick", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-6.q16", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-common", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-dbg", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-doc", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-perl", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-q16-perl", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6-headers", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-5", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-dev", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-headers", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2-extra", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-dev", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6-headers", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-2", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-dev", reference:"8:6.8.9.9-5+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"perlmagick", reference:"8:6.8.9.9-5+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
