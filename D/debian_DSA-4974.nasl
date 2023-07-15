#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4974. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153485);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-22895", "CVE-2021-32728");

  script_name(english:"Debian DSA-4974-1 : nextcloud-desktop - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4974 advisory.

  - Nextcloud Desktop Client before 3.3.1 is vulnerable to improper certificate validation due to lack of SSL
    certificate verification when using the Register with a Provider flow. (CVE-2021-22895)

  - The Nextcloud Desktop Client is a tool to synchronize files from Nextcloud Server with a computer. Clients
    using the Nextcloud end-to-end encryption feature download the public and private key via an API endpoint.
    In versions prior to 3.3.0, the Nextcloud Desktop client fails to check if a private key belongs to
    previously downloaded public certificate. If the Nextcloud instance serves a malicious public key, the
    data would be encrypted for this key and thus could be accessible to a malicious actor. This issue is
    fixed in Nextcloud Desktop Client version 3.3.0. There are no known workarounds aside from upgrading.
    (CVE-2021-32728)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=989846");
  # https://security-tracker.debian.org/tracker/source-package/nextcloud-desktop
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c0ae60e");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-22895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32728");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nextcloud-desktop");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/nextcloud-desktop");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nextcloud-desktop packages.

For the stable distribution (bullseye), these problems have been fixed in version 3.1.1-2+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22895");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-32728");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:caja-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dolphin-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnextcloudsync-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnextcloudsync0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nautilus-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nemo-nextcloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nextcloud-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nextcloud-desktop-cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nextcloud-desktop-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nextcloud-desktop-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nextcloud-desktop-l10n");
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
    {'release': '10.0', 'prefix': 'caja-nextcloud', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'dolphin-nextcloud', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'libnextcloudsync-dev', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'libnextcloudsync0', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nautilus-nextcloud', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nemo-nextcloud', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nextcloud-desktop', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nextcloud-desktop-cmd', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nextcloud-desktop-common', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nextcloud-desktop-doc', 'reference': '2.5.1-3+deb10u2'},
    {'release': '10.0', 'prefix': 'nextcloud-desktop-l10n', 'reference': '2.5.1-3+deb10u2'},
    {'release': '11.0', 'prefix': 'caja-nextcloud', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'dolphin-nextcloud', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libnextcloudsync-dev', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'libnextcloudsync0', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nautilus-nextcloud', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nemo-nextcloud', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nextcloud-desktop', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nextcloud-desktop-cmd', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nextcloud-desktop-common', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nextcloud-desktop-doc', 'reference': '3.1.1-2+deb11u1'},
    {'release': '11.0', 'prefix': 'nextcloud-desktop-l10n', 'reference': '3.1.1-2+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'caja-nextcloud / dolphin-nextcloud / libnextcloudsync-dev / etc');
}
