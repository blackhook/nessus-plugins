#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-4999. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154818);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/02");

  script_cve_id("CVE-2021-32558", "CVE-2021-32686");

  script_name(english:"Debian DSA-4999-1 : asterisk - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-4999 advisory.

  - An issue was discovered in Sangoma Asterisk 13.x before 13.38.3, 16.x before 16.19.1, 17.x before 17.9.4,
    and 18.x before 18.5.1, and Certified Asterisk before 16.8-cert10. If the IAX2 channel driver receives a
    packet that contains an unsupported media format, a crash can occur. (CVE-2021-32558)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In PJSIP before version 2.11.1, there
    are a couple of issues found in the SSL socket. First, a race condition between callback and destroy, due
    to the accepted socket having no group lock. Second, the SSL socket parent/listener may get destroyed
    during handshake. Both issues were reported to happen intermittently in heavy load TLS connections. They
    cause a crash, resulting in a denial of service. These are fixed in version 2.11.1. (CVE-2021-32686)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=991710");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/asterisk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4999");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32558");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32686");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/asterisk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the asterisk packages.

For the stable distribution (bullseye), these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32558");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dahdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-ooh323");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-imapstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-voicemail-odbcstorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:asterisk-vpb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'asterisk', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-config', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-dahdi', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-dev', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-doc', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-mobile', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-modules', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-mp3', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-mysql', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-ooh323', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-tests', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-voicemail', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-voicemail-imapstorage', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-voicemail-odbcstorage', 'reference': '1:16.16.1~dfsg-1+deb11u1'},
    {'release': '11.0', 'prefix': 'asterisk-vpb', 'reference': '1:16.16.1~dfsg-1+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'asterisk / asterisk-config / asterisk-dahdi / asterisk-dev / etc');
}
