#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1936. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44801);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0455", "CVE-2009-3546");
  script_bugtraq_id(36712);
  script_xref(name:"DSA", value:"1936");

  script_name(english:"Debian DSA-1936-1 : libgd2 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in libgd2, a library for
programmatic graphics creation and manipulation. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-0455
    Kees Cook discovered a buffer overflow in libgd2's font
    renderer. An attacker could cause denial of service
    (application crash) and possibly execute arbitrary code
    via a crafted string with a JIS encoded font. This issue
    only affects the oldstable distribution (etch).

  - CVE-2009-3546
    Tomas Hoger discovered a boundary error in the
    '_gdGetColors()' function. An attacker could conduct a
    buffer overflow or buffer over-read attacks via a
    crafted GD file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=408982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=552534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1936"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgd2 packages.

For the oldstable distribution (etch), these problems have been fixed
in version 2.0.33-5.2etch2.

For the stable distribution (lenny), these problems have been fixed in
version 2.0.36~rc1~dfsg-3+lenny1.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version
2.0.36~rc1~dfsg-3.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"4.0", prefix:"libgd-tools", reference:"2.0.33-5.2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-noxpm", reference:"2.0.33-5.2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-noxpm-dev", reference:"2.0.33-5.2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-xpm", reference:"2.0.33-5.2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-xpm-dev", reference:"2.0.33-5.2etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libgd-tools", reference:"2.0.36~rc1~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgd2-noxpm", reference:"2.0.36~rc1~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgd2-noxpm-dev", reference:"2.0.36~rc1~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgd2-xpm", reference:"2.0.36~rc1~dfsg-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgd2-xpm-dev", reference:"2.0.36~rc1~dfsg-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
