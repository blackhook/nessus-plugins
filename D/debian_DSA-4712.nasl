#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4712. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137912);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/06");

  script_cve_id("CVE-2019-10649", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-12974", "CVE-2019-12975", "CVE-2019-12976", "CVE-2019-12977", "CVE-2019-12978", "CVE-2019-12979", "CVE-2019-13135", "CVE-2019-13137", "CVE-2019-13295", "CVE-2019-13297", "CVE-2019-13300", "CVE-2019-13301", "CVE-2019-13304", "CVE-2019-13305", "CVE-2019-13307", "CVE-2019-13308", "CVE-2019-13309", "CVE-2019-13311", "CVE-2019-13454", "CVE-2019-14981", "CVE-2019-15139", "CVE-2019-15140", "CVE-2019-16708", "CVE-2019-16710", "CVE-2019-16711", "CVE-2019-16713", "CVE-2019-19948", "CVE-2019-19949", "CVE-2019-7175", "CVE-2019-7395", "CVE-2019-7396", "CVE-2019-7397", "CVE-2019-7398");
  script_xref(name:"DSA", value:"4712");

  script_name(english:"Debian DSA-4712-1 : imagemagick - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update fixes multiple vulnerabilities in Imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service, memory disclosure or
potentially the execution of arbitrary code if malformed image files
are processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/imagemagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4712"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the imagemagick packages.

For the stable distribution (buster), these problems have been fixed
in version 8:6.9.10.23+dfsg-2.1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");
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
if (deb_check(release:"10.0", prefix:"imagemagick", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"imagemagick-6-common", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"imagemagick-6-doc", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"imagemagick-6.q16", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"imagemagick-6.q16hdri", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"imagemagick-common", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"imagemagick-doc", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libimage-magick-perl", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libimage-magick-q16-perl", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libimage-magick-q16hdri-perl", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagick++-6-headers", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagick++-6.q16-8", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagick++-6.q16hdri-8", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagick++-6.q16hdri-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagick++-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6-headers", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6.q16-6", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6.q16-6-extra", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6.q16hdri-6", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6.q16hdri-6-extra", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-6.q16hdri-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickcore-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickwand-6-headers", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickwand-6.q16-6", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickwand-6.q16hdri-6", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickwand-6.q16hdri-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libmagickwand-dev", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"perlmagick", reference:"8:6.9.10.23+dfsg-2.1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
