#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3335. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171903);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id(
    "CVE-2022-23537",
    "CVE-2022-23547",
    "CVE-2022-31031",
    "CVE-2022-37325",
    "CVE-2022-39244",
    "CVE-2022-39269",
    "CVE-2022-42705",
    "CVE-2022-42706"
  );

  script_name(english:"Debian DLA-3335-1 : asterisk - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3335 advisory.

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. Buffer overread is possible when
    parsing a specially crafted STUN message with unknown attribute. The vulnerability affects applications
    that uses STUN including PJNATH and PJSUA-LIB. The patch is available as a commit in the master branch
    (2.13.1). (CVE-2022-23537)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. This issue is similar to
    GHSA-9pfh-r8x4-w26w. Possible buffer overread when parsing a certain STUN message. The vulnerability
    affects applications that uses STUN including PJNATH and PJSUA-LIB. The patch is available as commit in
    the master branch. (CVE-2022-23547)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In versions prior to and including
    2.12.1 a stack buffer overflow vulnerability affects PJSIP users that use STUN in their applications,
    either by: setting a STUN server in their account/media config in PJSUA/PJSUA2 level, or directly using
    `pjlib-util/stun_simple` API. A patch is available in commit 450baca which should be included in the next
    release. There are no known workarounds for this issue. (CVE-2022-31031)

  - In Sangoma Asterisk through 16.28.0, 17.x and 18.x through 18.14.0, and 19.x through 19.6.0, an incoming
    Setup message to addons/ooh323c/src/ooq931.c with a malformed Calling or Called Party IE can cause a
    crash. (CVE-2022-37325)

  - PJSIP is a free and open source multimedia communication library written in C. In versions of PJSIP prior
    to 2.13 the PJSIP parser, PJMEDIA RTP decoder, and PJMEDIA SDP parser are affeced by a buffer overflow
    vulnerability. Users connecting to untrusted clients are at risk. This issue has been patched and is
    available as commit c4d3498 in the master branch and will be included in releases 2.13 and later. Users
    are advised to upgrade. There are no known workarounds for this issue. (CVE-2022-39244)

  - PJSIP is a free and open source multimedia communication library written in C. When processing certain
    packets, PJSIP may incorrectly switch from using SRTP media transport to using basic RTP upon SRTP
    restart, causing the media to be sent insecurely. The vulnerability impacts all PJSIP users that use SRTP.
    The patch is available as commit d2acb9a in the master branch of the project and will be included in
    version 2.13. Users are advised to manually patch or to upgrade. There are no known workarounds for this
    vulnerability. (CVE-2022-39269)

  - A use-after-free in res_pjsip_pubsub.c in Sangoma Asterisk 16.28, 18.14, 19.6, and certified/18.9-cert2
    may allow a remote authenticated attacker to crash Asterisk (denial of service) by performing activity on
    a subscription via a reliable transport at the same time that Asterisk is also performing activity on that
    subscription. (CVE-2022-42705)

  - An issue was discovered in Sangoma Asterisk through 16.28, 17 and 18 through 18.14, 19 through 19.6, and
    certified through 18.9-cert1. GetConfig, via Asterisk Manager Interface, allows a connected application to
    access files outside of the asterisk configuration directory, aka Directory Traversal. (CVE-2022-42706)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/asterisk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3335");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23537");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23547");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31031");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37325");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39269");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42706");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/asterisk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the asterisk packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31031");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/24");

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
    {'release': '10.0', 'prefix': 'asterisk', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-config', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-dahdi', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-dev', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-doc', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-mobile', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-modules', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-mp3', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-mysql', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-ooh323', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-tests', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-voicemail', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-voicemail-imapstorage', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-voicemail-odbcstorage', 'reference': '1:16.28.0~dfsg-0+deb10u2'},
    {'release': '10.0', 'prefix': 'asterisk-vpb', 'reference': '1:16.28.0~dfsg-0+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'asterisk / asterisk-config / asterisk-dahdi / asterisk-dev / etc');
}
