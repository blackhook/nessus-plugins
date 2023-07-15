#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4095. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106319);
  script_version("1.3");
  script_cvs_date("Date: 2018/11/13 12:30:46");

  script_cve_id("CVE-2018-5345");
  script_xref(name:"DSA", value:"4095");

  script_name(english:"Debian DSA-4095-1 : gcab - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that gcab, a Microsoft Cabinet file manipulation
tool, is prone to a stack-based buffer overflow vulnerability when
extracting .cab files. An attacker can take advantage of this flaw to
cause a denial-of-service or, potentially the execution of arbitrary
code with the privileges of the user running gcab, if a specially
crafted .cab file is processed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=887776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/gcab"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/gcab"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gcab packages.

For the stable distribution (stretch), this problem has been fixed in
version 0.7-2+deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gcab");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"gcab", reference:"0.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-libgcab-1.0", reference:"0.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcab-1.0-0", reference:"0.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcab-dev", reference:"0.7-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libgcab-doc", reference:"0.7-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");