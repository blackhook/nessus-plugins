#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5080. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158201);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_cve_id("CVE-2021-44730", "CVE-2021-44731");

  script_name(english:"Debian DSA-5080-1 : snapd - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5080 advisory.

  - snapd 2.54.2 did not properly validate the location of the snap-confine binary. A local attacker who can
    hardlink this binary to another location to cause snap-confine to execute other arbitrary binaries and
    hence gain privilege escalation. Fixed in snapd versions 2.54.3+18.04, 2.54.3+20.04 and 2.54.3+21.10.1
    (CVE-2021-44730)

  - A race condition existed in the snapd 2.54.2 snap-confine binary when preparing a private mount namespace
    for a snap. This could allow a local attacker to gain root privileges by bind-mounting their own contents
    inside the snap's private mount namespace and causing snap-confine to execute arbitrary code and hence
    gain privilege escalation. Fixed in snapd versions 2.54.3+18.04, 2.54.3+20.04 and 2.54.3+21.10.1
    (CVE-2021-44731)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/snapd");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5080");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44730");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44731");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/snapd");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/snapd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the snapd packages.

For the stable distribution (bullseye), these problems have been fixed in version 2.49-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44731");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-44730");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-github-snapcore-snapd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-github-ubuntu-core-snappy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snap-confine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ubuntu-core-launcher");
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
    {'release': '10.0', 'prefix': 'golang-github-snapcore-snapd-dev', 'reference': '2.37.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'golang-github-ubuntu-core-snappy-dev', 'reference': '2.37.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'snap-confine', 'reference': '2.37.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'snapd', 'reference': '2.37.4-1+deb10u1'},
    {'release': '10.0', 'prefix': 'ubuntu-core-launcher', 'reference': '2.37.4-1+deb10u1'},
    {'release': '11.0', 'prefix': 'golang-github-snapcore-snapd-dev', 'reference': '2.49-1+deb11u1'},
    {'release': '11.0', 'prefix': 'golang-github-ubuntu-core-snappy-dev', 'reference': '2.49-1+deb11u1'},
    {'release': '11.0', 'prefix': 'snap-confine', 'reference': '2.49-1+deb11u1'},
    {'release': '11.0', 'prefix': 'snapd', 'reference': '2.49-1+deb11u1'},
    {'release': '11.0', 'prefix': 'ubuntu-core-launcher', 'reference': '2.49-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-github-snapcore-snapd-dev / etc');
}
