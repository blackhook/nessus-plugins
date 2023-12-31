#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1866. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44731);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0945", "CVE-2009-1709");
  script_bugtraq_id(34924, 35334);
  script_xref(name:"DSA", value:"1866");

  script_name(english:"Debian DSA-1866-1 : kdegraphics - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two security issues have been discovered in kdegraphics, the graphics
apps from the official KDE release. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2009-0945
    It was discovered that the KSVG animation element
    implementation suffers from a NULL pointer dereference
    flaw, which could lead to the execution of arbitrary
    code.

  - CVE-2009-1709
    It was discovered that the KSVG animation element
    implementation is prone to a use-after-free flaw, which
    could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=534951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1866"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdegraphics packages.

For the oldstable distribution (etch), these problems have been fixed
in version 4:3.5.5-3etch4.

For the stable distribution (lenny), these problems have been fixed in
version 4:3.5.9-3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/19");
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
if (deb_check(release:"4.0", prefix:"kamera", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kcoloredit", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dbg", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dev", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-doc-html", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-kfile-plugins", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kdvi", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kfax", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kfaxview", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kgamma", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kghostview", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kiconedit", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kmrml", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kolourpaint", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kooka", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kpdf", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kpovmodeler", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kruler", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ksnapshot", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ksvg", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kuickshow", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kview", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"kviewshell", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan-dev", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan1", reference:"4:3.5.5-3etch4")) flag++;
if (deb_check(release:"5.0", prefix:"kamera", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kcoloredit", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-dbg", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-dev", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-doc-html", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-kfile-plugins", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kdvi", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kfax", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kfaxview", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kgamma", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kghostview", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kiconedit", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kmrml", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kolourpaint", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kooka", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kpdf", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kpovmodeler", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kruler", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"ksnapshot", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"ksvg", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kuickshow", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kview", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"kviewshell", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libkscan-dev", reference:"4:3.5.9-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libkscan1", reference:"4:3.5.9-3+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
