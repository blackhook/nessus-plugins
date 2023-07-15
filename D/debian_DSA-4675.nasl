#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4675. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136371);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/11");

  script_cve_id("CVE-2019-12921", "CVE-2020-10938");
  script_xref(name:"DSA", value:"4675");

  script_name(english:"Debian DSA-4675-1 : graphicsmagick - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in GraphicsMagick, a set
of command-line applications to manipulate image files, which could
result in information disclosure, denial of service or the execution
of arbitrary code if malformed image files are processed."
  );
  # https://security-tracker.debian.org/tracker/source-package/graphicsmagick
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e247f871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/graphicsmagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/graphicsmagick"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4675"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the graphicsmagick packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1.3.30+hg15796-1~deb9u4.

For the stable distribution (buster), these problems have been fixed
in version 1.4+really1.3.35-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");
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
if (deb_check(release:"10.0", prefix:"graphicsmagick", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"graphicsmagick-dbg", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgraphics-magick-perl", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgraphicsmagick++-q16-12", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgraphicsmagick++1-dev", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgraphicsmagick-q16-3", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libgraphicsmagick1-dev", reference:"1.4+really1.3.35-1~deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick-dbg", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphics-magick-perl", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick++-q16-12", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick-q16-3", reference:"1.3.30+hg15796-1~deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.30+hg15796-1~deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
