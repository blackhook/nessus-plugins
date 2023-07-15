#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3309. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171060);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/07");

  script_cve_id("CVE-2022-4728", "CVE-2022-4729", "CVE-2022-4730");

  script_name(english:"Debian DLA-3309-1 : graphite-web - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3309 advisory.

  - A vulnerability has been found in Graphite Web and classified as problematic. This vulnerability affects
    unknown code of the component Cookie Handler. The manipulation leads to cross site scripting. The attack
    can be initiated remotely. The exploit has been disclosed to the public and may be used. The name of the
    patch is 2f178f490e10efc03cd1d27c72f64ecab224eb23. It is recommended to apply a patch to fix this issue.
    VDB-216742 is the identifier assigned to this vulnerability. (CVE-2022-4728)

  - A vulnerability was found in Graphite Web and classified as problematic. This issue affects some unknown
    processing of the component Template Name Handler. The manipulation leads to cross site scripting. The
    attack may be initiated remotely. The exploit has been disclosed to the public and may be used. The name
    of the patch is 2f178f490e10efc03cd1d27c72f64ecab224eb23. It is recommended to apply a patch to fix this
    issue. The associated identifier of this vulnerability is VDB-216743. (CVE-2022-4729)

  - A vulnerability was found in Graphite Web. It has been classified as problematic. Affected is an unknown
    function of the component Absolute Time Range Handler. The manipulation leads to cross site scripting. It
    is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used.
    The name of the patch is 2f178f490e10efc03cd1d27c72f64ecab224eb23. It is recommended to apply a patch to
    fix this issue. The identifier of this vulnerability is VDB-216744. (CVE-2022-4730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3309");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4728");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4730");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/graphite-web");
  script_set_attribute(attribute:"solution", value:
"Upgrade the graphite-web packages.

For Debian 10 Buster, these problems have been fixed in version 1.1.4-3+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphite-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'graphite-web', 'reference': '1.1.4-3+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'graphite-web');
}
