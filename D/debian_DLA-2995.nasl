#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2995. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160680);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2021-21408", "CVE-2021-29454");

  script_name(english:"Debian DLA-2995-1 : smarty3 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-2995 advisory.

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.43 and 4.0.3, template authors could run restricted static php
    methods. Users should upgrade to version 3.1.43 or 4.0.3 to receive a patch. (CVE-2021-21408)

  - Smarty is a template engine for PHP, facilitating the separation of presentation (HTML/CSS) from
    application logic. Prior to versions 3.1.42 and 4.0.2, template authors could run arbitrary PHP code by
    crafting a malicious math string. If a math string was passed through as user provided data to the math
    function, external users could run arbitrary PHP code by crafting a malicious math string. Users should
    upgrade to version 3.1.42 or 4.0.2 to receive a patch. (CVE-2021-29454)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1010375");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/smarty3");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2995");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21408");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29454");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/smarty3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the smarty3 packages.

For Debian 9 stretch, these problems have been fixed in version 3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29454");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:smarty3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'smarty3', 'reference': '3.1.31+20161214.1.c7d42e4+selfpack1-2+deb9u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'smarty3');
}
