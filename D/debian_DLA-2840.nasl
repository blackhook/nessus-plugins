#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2840. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155924);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2021-44025", "CVE-2021-44026");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/07/13");

  script_name(english:"Debian DLA-2840-1 : roundcube - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2840 advisory.

  - Roundcube before 1.3.17 and 1.4.x before 1.4.12 is prone to XSS in handling an attachment's filename
    extension when displaying a MIME type warning message. (CVE-2021-44025)

  - Roundcube before 1.3.17 and 1.4.x before 1.4.12 is prone to a potential SQL injection via search or
    search_params. (CVE-2021-44026)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1000156");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/roundcube");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44025");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44026");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/roundcube");
  script_set_attribute(attribute:"solution", value:
"Upgrade the roundcube packages.

For Debian 9 stretch, these problems have been fixed in version 1.2.3+dfsg.1-4+deb9u9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44026");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube-sqlite3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'roundcube', 'reference': '1.2.3+dfsg.1-4+deb9u9'},
    {'release': '9.0', 'prefix': 'roundcube-core', 'reference': '1.2.3+dfsg.1-4+deb9u9'},
    {'release': '9.0', 'prefix': 'roundcube-mysql', 'reference': '1.2.3+dfsg.1-4+deb9u9'},
    {'release': '9.0', 'prefix': 'roundcube-pgsql', 'reference': '1.2.3+dfsg.1-4+deb9u9'},
    {'release': '9.0', 'prefix': 'roundcube-plugins', 'reference': '1.2.3+dfsg.1-4+deb9u9'},
    {'release': '9.0', 'prefix': 'roundcube-sqlite3', 'reference': '1.2.3+dfsg.1-4+deb9u9'}
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
    severity   : SECURITY_HOLE,
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
