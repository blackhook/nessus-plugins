#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2793. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154627);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/28");

  script_cve_id("CVE-2017-7655");

  script_name(english:"Debian DLA-2793-1 : mosquitto - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2793
advisory.

  - In Eclipse Mosquitto version from 1.0 to 1.4.15, a Null Dereference vulnerability was found in the
    Mosquitto library which could lead to crashes for those applications using the library. (CVE-2017-7655)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mosquitto");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2793");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-7655");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/mosquitto");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mosquitto packages.

For Debian 9 stretch, this problem has been fixed in version 1.4.10-3+deb9u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7655");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquitto1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmosquittopp1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mosquitto-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libmosquitto-dev', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'libmosquitto1', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'libmosquitto1-dbg', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'libmosquittopp-dev', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'libmosquittopp1', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'libmosquittopp1-dbg', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'mosquitto', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'mosquitto-clients', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'mosquitto-dbg', 'reference': '1.4.10-3+deb9u5'},
    {'release': '9.0', 'prefix': 'mosquitto-dev', 'reference': '1.4.10-3+deb9u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmosquitto-dev / libmosquitto1 / libmosquitto1-dbg / etc');
}
