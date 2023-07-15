#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5407. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(176198);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-24805");

  script_name(english:"Debian DSA-5407-1 : cups-filters - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5407
advisory.

  - cups-filters contains backends, filters, and other software required to get the cups printing service
    working on operating systems other than macos. If you use the Backend Error Handler (beh) to create an
    accessible network printer, this security vulnerability can cause remote code execution. `beh.c` contains
    the line `retval = system(cmdline) >> 8;` which calls the `system` command with the operand `cmdline`.
    `cmdline` contains multiple user controlled, unsanitized values. As a result an attacker with network
    access to the hosted print server can exploit this vulnerability to inject system commands which are
    executed in the context of the running server. This issue has been addressed in commit `8f2740357` and is
    expected to be bundled in the next release. Users are advised to upgrade when possible and to restrict
    access to network printers in the meantime. (CVE-2023-24805)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1036224");
  # https://security-tracker.debian.org/tracker/source-package/cups-filters
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62e18b04");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5407");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-24805");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/cups-filters");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cups-filters packages.

For the stable distribution (bullseye), this problem has been fixed in version 1.28.7-1+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24805");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-browsed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups-filters-core-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsfilters-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcupsfilters1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfontembed-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfontembed1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'cups-browsed', 'reference': '1.28.7-1+deb11u2'},
    {'release': '11.0', 'prefix': 'cups-filters', 'reference': '1.28.7-1+deb11u2'},
    {'release': '11.0', 'prefix': 'cups-filters-core-drivers', 'reference': '1.28.7-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libcupsfilters-dev', 'reference': '1.28.7-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libcupsfilters1', 'reference': '1.28.7-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libfontembed-dev', 'reference': '1.28.7-1+deb11u2'},
    {'release': '11.0', 'prefix': 'libfontembed1', 'reference': '1.28.7-1+deb11u2'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cups-browsed / cups-filters / cups-filters-core-drivers / etc');
}
