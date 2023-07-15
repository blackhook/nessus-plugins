#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5065. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157320);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/02");

  script_cve_id("CVE-2022-21699");

  script_name(english:"Debian DSA-5065-1 : ipython - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5065
advisory.

  - IPython (Interactive Python) is a command shell for interactive computing in multiple programming
    languages, originally developed for the Python programming language. Affected versions are subject to an
    arbitrary code execution vulnerability achieved by not properly managing cross user temporary files. This
    vulnerability allows one user to run code as another on the same machine. All users are advised to
    upgrade. (CVE-2022-21699)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ipython");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5065");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21699");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ipython");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ipython");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ipython packages.

For the stable distribution (bullseye), this problem has been fixed in version 7.20.0-1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ipython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-ipython-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-ipython");
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
    {'release': '10.0', 'prefix': 'ipython', 'reference': '5.8.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'ipython3', 'reference': '5.8.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-ipython', 'reference': '5.8.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python-ipython-doc', 'reference': '5.8.0-1+deb10u1'},
    {'release': '10.0', 'prefix': 'python3-ipython', 'reference': '5.8.0-1+deb10u1'},
    {'release': '11.0', 'prefix': 'ipython', 'reference': '7.20.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'ipython3', 'reference': '7.20.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python-ipython', 'reference': '7.20.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python-ipython-doc', 'reference': '7.20.0-1+deb11u1'},
    {'release': '11.0', 'prefix': 'python3-ipython', 'reference': '7.20.0-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipython / ipython3 / python-ipython / python-ipython-doc / etc');
}
