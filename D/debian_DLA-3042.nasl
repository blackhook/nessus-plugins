#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3042. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161837);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-20770",
    "CVE-2022-20771",
    "CVE-2022-20785",
    "CVE-2022-20792",
    "CVE-2022-20796"
  );

  script_name(english:"Debian DLA-3042-1 : clamav - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3042 advisory.

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in HTML file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20785)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in CHM file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20770)

  - On April 20, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in the TIFF file parser of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an
    unauthenticated, remote attacker to cause a denial of service condition on an affected device. For a
    description of this vulnerability, see the ClamAV blog. This advisory will be updated as additional
    information becomes available. (CVE-2022-20771)

  - A vulnerability in the regex module used by the signature database load module of Clam AntiVirus (ClamAV)
    versions 0.104.0 through 0.104.2 and LTS version 0.103.5 and prior versions could allow an authenticated,
    local attacker to crash ClamAV at database load time, and possibly gain code execution. The vulnerability
    is due to improper bounds checking that may result in a multi-byte heap buffer overwflow write. An
    attacker could exploit this vulnerability by placing a crafted CDB ClamAV signature database file in the
    ClamAV database directory. An exploit could allow the attacker to run code as the clamav user.
    (CVE-2022-20792)

  - On May 4, 2022, the following vulnerability in the ClamAV scanning library versions 0.103.5 and earlier
    and 0.104.2 and earlier was disclosed: A vulnerability in Clam AntiVirus (ClamAV) versions 0.103.4,
    0.103.5, 0.104.1, and 0.104.2 could allow an authenticated, local attacker to cause a denial of service
    condition on an affected device. For a description of this vulnerability, see the ClamAV blog.
    (CVE-2022-20796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/clamav");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3042");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-20796");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/clamav");
  script_set_attribute(attribute:"solution", value:
"Upgrade the clamav packages.

For Debian 9 stretch, these problems have been fixed in version 0.103.6+dfsg-0+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20785");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-20792");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamdscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'clamav', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-base', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-daemon', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-docs', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-freshclam', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-milter', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamav-testfiles', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'clamdscan', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'libclamav-dev', 'reference': '0.103.6+dfsg-0+deb9u1'},
    {'release': '9.0', 'prefix': 'libclamav9', 'reference': '0.103.6+dfsg-0+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'clamav / clamav-base / clamav-daemon / clamav-docs / clamav-freshclam / etc');
}
