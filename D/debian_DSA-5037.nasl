#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5037. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156564);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/09");

  script_cve_id("CVE-2021-46144");

  script_name(english:"Debian DSA-5037-1 : roundcube - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5037
advisory.

  - Roundcube before 1.4.13 and 1.5.x before 1.5.2 allows XSS via an HTML e-mail message with crafted
    Cascading Style Sheets (CSS) token sequences. (CVE-2021-46144)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1003027");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/roundcube");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5037");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46144");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/roundcube");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/roundcube");
  script_set_attribute(attribute:"solution", value:
"Upgrade the roundcube packages.

For the stable distribution (bullseye), this problem has been fixed in version 1.4.13+dfsg.1-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'roundcube', 'reference': '1.3.17+dfsg.1-1~deb10u2'},
    {'release': '10.0', 'prefix': 'roundcube-core', 'reference': '1.3.17+dfsg.1-1~deb10u2'},
    {'release': '10.0', 'prefix': 'roundcube-mysql', 'reference': '1.3.17+dfsg.1-1~deb10u2'},
    {'release': '10.0', 'prefix': 'roundcube-pgsql', 'reference': '1.3.17+dfsg.1-1~deb10u2'},
    {'release': '10.0', 'prefix': 'roundcube-plugins', 'reference': '1.3.17+dfsg.1-1~deb10u2'},
    {'release': '10.0', 'prefix': 'roundcube-sqlite3', 'reference': '1.3.17+dfsg.1-1~deb10u2'},
    {'release': '11.0', 'prefix': 'roundcube', 'reference': '1.4.13+dfsg.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'roundcube-core', 'reference': '1.4.13+dfsg.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'roundcube-mysql', 'reference': '1.4.13+dfsg.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'roundcube-pgsql', 'reference': '1.4.13+dfsg.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'roundcube-plugins', 'reference': '1.4.13+dfsg.1-1~deb11u1'},
    {'release': '11.0', 'prefix': 'roundcube-sqlite3', 'reference': '1.4.13+dfsg.1-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'roundcube / roundcube-core / roundcube-mysql / roundcube-pgsql / etc');
}
