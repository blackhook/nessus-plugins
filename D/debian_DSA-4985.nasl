#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4985. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154159);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-39200", "CVE-2021-39201");

  script_name(english:"Debian DSA-4985-1 : wordpress - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4985 advisory.

  - WordPress is a free and open-source content management system written in PHP and paired with a MySQL or
    MariaDB database. In affected versions output data of the function wp_die() can be leaked under certain
    conditions, which can include data like nonces. It can then be used to perform actions on your behalf.
    This has been patched in WordPress 5.8.1, along with any older affected versions via minor releases. It's
    strongly recommended that you keep auto-updates enabled to receive the fix. (CVE-2021-39200)

  - WordPress is a free and open-source content management system written in PHP and paired with a MySQL or
    MariaDB database. ### Impact The issue allows an authenticated but low-privileged user (like
    contributor/author) to execute XSS in the editor. This bypasses the restrictions imposed on users who do
    not have the permission to post `unfiltered_html`. ### Patches This has been patched in WordPress 5.8, and
    will be pushed to older versions via minor releases (automatic updates). It's strongly recommended that
    you keep auto-updates enabled to receive the fix. ### References
    https://wordpress.org/news/category/releases/ https://hackerone.com/reports/1142140 ### For more
    information If you have any questions or comments about this advisory: * Open an issue in
    [HackerOne](https://hackerone.com/wordpress) (CVE-2021-39201)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=994059");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4985");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39200");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-39201");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/wordpress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wordpress packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.7.3+dfsg1-0+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39200");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-39201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentynineteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyseventeen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentysixteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwenty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentytwentyone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'wordpress', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-l10n', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentynineteen', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentyseventeen', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentysixteen', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentytwenty', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '10.0', 'prefix': 'wordpress-theme-twentytwentyone', 'reference': '5.0.14+dfsg1-0+deb10u1'},
    {'release': '11.0', 'prefix': 'wordpress', 'reference': '5.7.3+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-l10n', 'reference': '5.7.3+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentynineteen', 'reference': '5.7.3+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentyseventeen', 'reference': '5.7.3+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentysixteen', 'reference': '5.7.3+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentytwenty', 'reference': '5.7.3+dfsg1-0+deb11u1'},
    {'release': '11.0', 'prefix': 'wordpress-theme-twentytwentyone', 'reference': '5.7.3+dfsg1-0+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wordpress / wordpress-l10n / wordpress-theme-twentynineteen / etc');
}
