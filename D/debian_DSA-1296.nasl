#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1296. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25300);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-2509");
  script_xref(name:"DSA", value:"1296");

  script_name(english:"Debian DSA-1296-1 : php4 - missing input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the ftp extension of PHP, a server-side,
HTML-embedded scripting language performs insufficient input
sanitising, which permits an attacker to execute arbitrary FTP
commands. This requires the attacker to already have access to the FTP
server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2007/dsa-1296"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PHP packages. Packages for the Sparc architectures are not
yet available, due to problems on the build host. They will be
provided later.

For the oldstable distribution (sarge) this problem has been fixed in
version 4.3.10-21.

For the stable distribution (etch) this problem has been fixed in
version 4.4.4-8+etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"3.1", prefix:"libapache-mod-php4", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"libapache2-mod-php4", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cgi", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cli", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-common", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-curl", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-dev", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-domxml", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-gd", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-imap", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-ldap", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mcal", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mhash", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mysql", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-odbc", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-pear", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-recode", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-snmp", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-sybase", reference:"4.3.10-21")) flag++;
if (deb_check(release:"3.1", prefix:"php4-xslt", reference:"4.3.10-21")) flag++;
if (deb_check(release:"4.0", prefix:"libapache-mod-php4", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libapache2-mod-php4", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cgi", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-cli", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-common", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-curl", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-dev", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-domxml", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-gd", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-imap", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-interbase", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-ldap", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcal", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mcrypt", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mhash", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-mysql", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-odbc", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pear", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pgsql", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-pspell", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-recode", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-snmp", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-sybase", reference:"4.4.4-8+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"php4-xslt", reference:"4.4.4-8+etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
