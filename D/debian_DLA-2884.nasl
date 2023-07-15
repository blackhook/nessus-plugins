#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2884. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156965);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2022-21661",
    "CVE-2022-21662",
    "CVE-2022-21663",
    "CVE-2022-21664"
  );
  script_xref(name:"IAVA", value:"2022-A-0003-S");

  script_name(english:"Debian DLA-2884-1 : wordpress - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2884 advisory.

  - WordPress is a free and open-source content management system written in PHP and paired with a MariaDB
    database. Due to improper sanitization in WP_Query, there can be cases where SQL injection is possible
    through plugins or themes that use it in a certain way. This has been patched in WordPress version 5.8.3.
    Older affected versions are also fixed via security release, that go back till 3.7.37. We strongly
    recommend that you keep auto-updates enabled. There are no known workarounds for this vulnerability.
    (CVE-2022-21661)

  - WordPress is a free and open-source content management system written in PHP and paired with a MariaDB
    database. Low-privileged authenticated users (like author) in WordPress core are able to execute
    JavaScript/perform stored XSS attack, which can affect high-privileged users. This has been patched in
    WordPress version 5.8.3. Older affected versions are also fixed via security release, that go back till
    3.7.37. We strongly recommend that you keep auto-updates enabled. There are no known workarounds for this
    issue. (CVE-2022-21662)

  - WordPress is a free and open-source content management system written in PHP and paired with a MariaDB
    database. On a multisite, users with Super Admin role can bypass explicit/additional hardening under
    certain conditions through object injection. This has been patched in WordPress version 5.8.3. Older
    affected versions are also fixed via security release, that go back till 3.7.37. We strongly recommend
    that you keep auto-updates enabled. There are no known workarounds for this issue. (CVE-2022-21663)

  - WordPress is a free and open-source content management system written in PHP and paired with a MariaDB
    database. Due to lack of proper sanitization in one of the classes, there's potential for unintended SQL
    queries to be executed. This has been patched in WordPress version 5.8.3. Older affected versions are also
    fixed via security release, that go back till 4.1.34. We strongly recommend that you keep auto-updates
    enabled. There are no known workarounds for this issue. (CVE-2022-21664)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1003243");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2884");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21661");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21662");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21663");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21664");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/wordpress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wordpress packages.

For Debian 9 stretch, these problems have been fixed in version 4.7.22+dfsg-0+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21664");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyfifteen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentyseventeen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-theme-twentysixteen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'wordpress', 'reference': '4.7.22+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'wordpress-l10n', 'reference': '4.7.22+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'wordpress-theme-twentyfifteen', 'reference': '4.7.22+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'wordpress-theme-twentyseventeen', 'reference': '4.7.22+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'wordpress-theme-twentysixteen', 'reference': '4.7.22+dfsg-0+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wordpress / wordpress-l10n / wordpress-theme-twentyfifteen / etc');
}
