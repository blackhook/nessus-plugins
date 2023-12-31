#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1889. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44754);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0153");
  script_xref(name:"DSA", value:"1889");

  script_name(english:"Debian DSA-1889-1 : icu - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the ICU unicode library performed incorrect
processing of invalid multibyte sequences, resulting in potential
bypass of security mechanisms."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2009/dsa-1889"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icu packages.

For the old stable distribution (etch), this problem has been fixed in
version 3.6-2etch3.

For the stable distribution (lenny), this problem has been fixed in
version 3.8.1-3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/16");
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
if (deb_check(release:"4.0", prefix:"icu-doc", reference:"3.6-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libicu36", reference:"3.6-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libicu36-dev", reference:"3.6-2etch3")) flag++;
if (deb_check(release:"5.0", prefix:"icu-doc", reference:"3.8.1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"lib32icu-dev", reference:"3.8.1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"lib32icu38", reference:"3.8.1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libicu-dev", reference:"3.8.1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libicu38", reference:"3.8.1-3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libicu38-dbg", reference:"3.8.1-3+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
