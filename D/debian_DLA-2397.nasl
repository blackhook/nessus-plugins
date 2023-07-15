#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2397-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141247);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2020-7070");
  script_xref(name:"IAVA", value:"2020-A-0445-S");

  script_name(english:"Debian DLA-2397-1 : php7.0 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability was discovered in PHP, a server-side, HTML-embedded
scripting language. When PHP is processing incoming HTTP cookie
values, the cookie names are url-decoded. This may lead to cookies
with prefixes like __Host confused with cookies that decode to such
prefix, thus leading to an attacker being able to forge a cookie which
is supposed to be secure.

For Debian 9 stretch, this problem has been fixed in version
7.0.33-0+deb9u10.

We recommend that you upgrade your php7.0 packages.

For the detailed security status of php7.0 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/php7.0

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00008.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/php7.0");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.0");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7070");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp7.0-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-opcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.0-zip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"9.0", prefix:"libapache2-mod-php7.0", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"libphp7.0-embed", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-bcmath", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-bz2", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-cgi", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-cli", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-common", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-curl", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-dba", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-dev", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-enchant", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-fpm", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-gd", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-gmp", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-imap", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-interbase", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-intl", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-json", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-ldap", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-mbstring", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-mcrypt", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-mysql", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-odbc", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-opcache", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-pgsql", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-phpdbg", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-pspell", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-readline", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-recode", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-snmp", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-soap", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-sqlite3", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-sybase", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-tidy", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-xml", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-xmlrpc", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-xsl", reference:"7.0.33-0+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"php7.0-zip", reference:"7.0.33-0+deb9u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
