#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-207. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15044);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2002-0836");
  script_xref(name:"DSA", value:"207");

  script_name(english:"Debian DSA-207-1 : tetex-bin - arbitrary command execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SuSE security team discovered a vulnerability in kpathsea library
(libkpathsea) which is used by xdvi and dvips. Both programs call the
system() function insecurely, which allows a remote attacker to
execute arbitrary commands via cleverly crafted DVI files.

If dvips is used in a print filter, this allows a local or remote
attacker with print permission execute arbitrary code as the printer
user (usually lp)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-207"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tetex-lib package immediately.

This problem has been fixed in version 1.0.7+20011202-7.1 for the
current stable distribution (woody), in version 1.0.6-7.3 for the old
stable distribution (potato) and in version 1.0.7+20021025-4 for the
unstable distribution (sid). xdvik-ja and dvipsk-ja are vulnerable as
well, but link to the kpathsea library dynamically and will
automatically be fixed after a new libkpathsea is installed."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tetex-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"tetex-bin", reference:"1.0.6-7.3")) flag++;
if (deb_check(release:"2.2", prefix:"tetex-dev", reference:"1.0.6-7.3")) flag++;
if (deb_check(release:"2.2", prefix:"tetex-lib", reference:"1.0.6-7.3")) flag++;
if (deb_check(release:"3.0", prefix:"libkpathsea-dev", reference:"1.0.7+20011202-7.1")) flag++;
if (deb_check(release:"3.0", prefix:"libkpathsea3", reference:"1.0.7+20011202-7.1")) flag++;
if (deb_check(release:"3.0", prefix:"tetex-bin", reference:"1.0.7+20011202-7.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
