#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3036. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161794);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/02");

  script_cve_id("CVE-2022-24763", "CVE-2022-24792", "CVE-2022-24793");

  script_name(english:"Debian DLA-3036-1 : pjproject - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3036 advisory.

  - PJSIP is a free and open source multimedia communication library written in the C language. Versions 2.12
    and prior contain a denial-of-service vulnerability that affects PJSIP users that consume PJSIP's XML
    parsing in their apps. Users are advised to update. There are no known workarounds. (CVE-2022-24763)

  - PJSIP is a free and open source multimedia communication library written in C. A denial-of-service
    vulnerability affects applications on a 32-bit systems that use PJSIP versions 2.12 and prior to play/read
    invalid WAV files. The vulnerability occurs when reading WAV file data chunks with length greater than
    31-bit integers. The vulnerability does not affect 64-bit apps and should not affect apps that only plays
    trusted WAV files. A patch is available on the `master` branch of the `pjsip/project` GitHub repository.
    As a workaround, apps can reject a WAV file received from an unknown source or validate the file first.
    (CVE-2022-24792)

  - PJSIP is a free and open source multimedia communication library written in C. A buffer overflow
    vulnerability in versions 2.12 and prior affects applications that uses PJSIP DNS resolution. It doesn't
    affect PJSIP users who utilize an external resolver. A patch is available in the `master` branch of the
    `pjsip/pjproject` GitHub repository. A workaround is to disable DNS resolution in PJSIP config (by setting
    `nameserver_count` to zero) or use an external resolver instead. (CVE-2022-24793)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pjproject");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3036");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24793");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/pjproject");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pjproject packages.

For Debian 9 stretch, these problems have been fixed in version 2.5.5~dfsg-6+deb9u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24763");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-24793");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpj2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjlib-util2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjmedia-audiodev2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjmedia-codec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjmedia-videodev2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjmedia2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjnath2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjproject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjsip-simple2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjsip-ua2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjsip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjsua2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpjsua2-2v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-pjproject");
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
    {'release': '9.0', 'prefix': 'libpj2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjlib-util2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjmedia-audiodev2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjmedia-codec2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjmedia-videodev2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjmedia2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjnath2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjproject-dev', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjsip-simple2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjsip-ua2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjsip2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjsua2', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'libpjsua2-2v5', 'reference': '2.5.5~dfsg-6+deb9u5'},
    {'release': '9.0', 'prefix': 'python-pjproject', 'reference': '2.5.5~dfsg-6+deb9u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpj2 / libpjlib-util2 / libpjmedia-audiodev2 / libpjmedia-codec2 / etc');
}
