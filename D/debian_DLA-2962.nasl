#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2962. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159329);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/30");

  script_cve_id(
    "CVE-2021-32686",
    "CVE-2021-37706",
    "CVE-2021-41141",
    "CVE-2021-43299",
    "CVE-2021-43300",
    "CVE-2021-43301",
    "CVE-2021-43302",
    "CVE-2021-43303",
    "CVE-2021-43804",
    "CVE-2021-43845",
    "CVE-2022-21722",
    "CVE-2022-21723",
    "CVE-2022-23608",
    "CVE-2022-24754",
    "CVE-2022-24764"
  );

  script_name(english:"Debian DLA-2962-1 : pjproject - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2962 advisory.

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In PJSIP before version 2.11.1, there
    are a couple of issues found in the SSL socket. First, a race condition between callback and destroy, due
    to the accepted socket having no group lock. Second, the SSL socket parent/listener may get destroyed
    during handshake. Both issues were reported to happen intermittently in heavy load TLS connections. They
    cause a crash, resulting in a denial of service. These are fixed in version 2.11.1. (CVE-2021-32686)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In affected versions if the incoming
    STUN message contains an ERROR-CODE attribute, the header length is not checked before performing a
    subtraction operation, potentially resulting in an integer underflow scenario. This issue affects all
    users that use STUN. A malicious actor located within the victim's network may forge and send a specially
    crafted UDP (STUN) message that could remotely execute arbitrary code on the victim's machine. Users are
    advised to upgrade as soon as possible. There are no known workarounds. (CVE-2021-37706)

  - PJSIP is a free and open source multimedia communication library written in the C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In various parts of PJSIP, when
    error/failure occurs, it is found that the function returns without releasing the currently held locks.
    This could result in a system deadlock, which cause a denial of service for the users. No release has yet
    been made which contains the linked fix commit. All versions up to an including 2.11.1 are affected. Users
    may need to manually apply the patch. (CVE-2021-41141)

  - Stack overflow in PJSUA API when calling pjsua_player_create. An attacker-controlled 'filename' argument
    may cause a buffer overflow since it is copied to a fixed-size stack buffer without any size validation.
    (CVE-2021-43299)

  - Stack overflow in PJSUA API when calling pjsua_recorder_create. An attacker-controlled 'filename' argument
    may cause a buffer overflow since it is copied to a fixed-size stack buffer without any size validation.
    (CVE-2021-43300)

  - Stack overflow in PJSUA API when calling pjsua_playlist_create. An attacker-controlled 'file_names'
    argument may cause a buffer overflow since it is copied to a fixed-size stack buffer without any size
    validation. (CVE-2021-43301)

  - Read out-of-bounds in PJSUA API when calling pjsua_recorder_create. An attacker-controlled 'filename'
    argument may cause an out-of-bounds read when the filename is shorter than 4 characters. (CVE-2021-43302)

  - Buffer overflow in PJSUA API when calling pjsua_call_dump. An attacker-controlled 'buffer' argument may
    cause a buffer overflow, since supplying an output buffer smaller than 128 characters may overflow the
    output buffer, regardless of the 'maxlen' argument supplied (CVE-2021-43303)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In affected versions if the incoming
    RTCP BYE message contains a reason's length, this declared length is not checked against the actual
    received packet size, potentially resulting in an out-of-bound read access. This issue affects all users
    that use PJMEDIA and RTCP. A malicious actor can send a RTCP BYE message with an invalid reason length.
    Users are advised to upgrade as soon as possible. There are no known workarounds. (CVE-2021-43804)

  - PJSIP is a free and open source multimedia communication library. In version 2.11.1 and prior, if incoming
    RTCP XR message contain block, the data field is not checked against the received packet size, potentially
    resulting in an out-of-bound read access. This affects all users that use PJMEDIA and RTCP XR. A malicious
    actor can send a RTCP XR message with an invalid packet size. (CVE-2021-43845)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In version 2.11.1 and prior, there
    are various cases where it is possible that certain incoming RTP/RTCP packets can potentially cause out-
    of-bound read access. This issue affects all users that use PJMEDIA and accept incoming RTP/RTCP. A patch
    is available as a commit in the `master` branch. There are no known workarounds. (CVE-2022-21722)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In versions 2.11.1 and prior, parsing
    an incoming SIP message that contains a malformed multipart can potentially cause out-of-bound read
    access. This issue affects all PJSIP users that accept SIP multipart. The patch is available as commit in
    the `master` branch. There are no known workarounds. (CVE-2022-21723)

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In versions up to and including
    2.11.1 when in a dialog set (or forking) scenario, a hash key shared by multiple UAC dialogs can
    potentially be prematurely freed when one of the dialogs is destroyed . The issue may cause a dialog set
    to be registered in the hash table multiple times (with different hash keys) leading to undefined behavior
    such as dialog list collision which eventually leading to endless loop. A patch is available in commit
    db3235953baa56d2fb0e276ca510fefca751643f which will be included in the next release. There are no known
    workarounds for this issue. (CVE-2022-23608)

  - PJSIP is a free and open source multimedia communication library written in C language. In versions prior
    to and including 2.12 PJSIP there is a stack-buffer overflow vulnerability which only impacts PJSIP users
    who accept hashed digest credentials (credentials with data_type `PJSIP_CRED_DATA_DIGEST`). This issue has
    been patched in the master branch of the PJSIP repository and will be included with the next release.
    Users unable to upgrade need to check that the hashed digest data length must be equal to
    `PJSIP_MD5STRLEN` before passing to PJSIP. (CVE-2022-24754)

  - PJSIP is a free and open source multimedia communication library written in C. Versions 2.12 and prior
    contain a stack buffer overflow vulnerability that affects PJSUA2 users or users that call the API
    `pjmedia_sdp_print(), pjmedia_sdp_media_print()`. Applications that do not use PJSUA2 and do not directly
    call `pjmedia_sdp_print()` or `pjmedia_sdp_media_print()` should not be affected. A patch is available on
    the `master` branch of the `pjsip/pjproject` GitHub repository. There are currently no known workarounds.
    (CVE-2022-24764)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pjproject");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2962");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32686");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43300");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43301");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24754");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24764");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/pjproject");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pjproject packages.

For Debian 9 stretch, these problems have been fixed in version 2.5.5~dfsg-6+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/30");

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
    {'release': '9.0', 'prefix': 'libpj2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjlib-util2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjmedia-audiodev2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjmedia-codec2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjmedia-videodev2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjmedia2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjnath2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjproject-dev', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjsip-simple2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjsip-ua2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjsip2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjsua2', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'libpjsua2-2v5', 'reference': '2.5.5~dfsg-6+deb9u3'},
    {'release': '9.0', 'prefix': 'python-pjproject', 'reference': '2.5.5~dfsg-6+deb9u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpj2 / libpjlib-util2 / libpjmedia-audiodev2 / libpjmedia-codec2 / etc');
}
