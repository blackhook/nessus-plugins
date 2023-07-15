#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3074. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164279);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/18");

  script_cve_id(
    "CVE-2021-45085",
    "CVE-2021-45087",
    "CVE-2021-45088",
    "CVE-2022-29536"
  );

  script_name(english:"Debian DLA-3074-1 : epiphany-browser - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3074 advisory.

  - XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1 via an about: page, as
    demonstrated by ephy-about:overview when a user visits an XSS payload page often enough to place that page
    on the Most Visited list. (CVE-2021-45085)

  - XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1 when View Source mode or Reader
    mode is used, as demonstrated by a a page title. (CVE-2021-45087)

  - XSS can occur in GNOME Web (aka Epiphany) before 40.4 and 41.x before 41.1 via an error page.
    (CVE-2021-45088)

  - In GNOME Epiphany before 41.4 and 42.x before 42.2, an HTML document can trigger a client buffer overflow
    (in ephy_string_shorten in the UI process) via a long page title. The issue occurs because the number of
    bytes for a UTF-8 ellipsis character is not properly considered. (CVE-2022-29536)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1009959");
  # https://security-tracker.debian.org/tracker/source-package/epiphany-browser
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?699d342c");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3074");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45087");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-45088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29536");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/epiphany-browser");
  script_set_attribute(attribute:"solution", value:
"Upgrade the epiphany-browser packages.

For Debian 10 buster, these problems have been fixed in version 3.32.1.2-3~deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:epiphany-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:epiphany-browser-data");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'epiphany-browser', 'reference': '3.32.1.2-3~deb10u2'},
    {'release': '10.0', 'prefix': 'epiphany-browser-data', 'reference': '3.32.1.2-3~deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'epiphany-browser / epiphany-browser-data');
}
