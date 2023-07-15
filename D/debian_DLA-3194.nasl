#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3194. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(167926);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/19");

  script_cve_id(
    "CVE-2021-37706",
    "CVE-2021-43299",
    "CVE-2021-43300",
    "CVE-2021-43301",
    "CVE-2021-43302",
    "CVE-2021-43303",
    "CVE-2021-43804",
    "CVE-2021-43845",
    "CVE-2021-46837",
    "CVE-2022-21722",
    "CVE-2022-21723",
    "CVE-2022-23608",
    "CVE-2022-24763",
    "CVE-2022-24764",
    "CVE-2022-24786",
    "CVE-2022-24792",
    "CVE-2022-24793",
    "CVE-2022-26498",
    "CVE-2022-26499",
    "CVE-2022-26651"
  );

  script_name(english:"Debian DLA-3194-1 : asterisk - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3194 advisory.

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In affected versions if the incoming
    STUN message contains an ERROR-CODE attribute, the header length is not checked before performing a
    subtraction operation, potentially resulting in an integer underflow scenario. This issue affects all
    users that use STUN. A malicious actor located within the victim's network may forge and send a specially
    crafted UDP (STUN) message that could remotely execute arbitrary code on the victim's machine. Users are
    advised to upgrade as soon as possible. There are no known workarounds. (CVE-2021-37706)

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

  - res_pjsip_t38 in Sangoma Asterisk 16.x before 16.16.2, 17.x before 17.9.3, and 18.x before 18.2.2, and
    Certified Asterisk before 16.8-cert7, allows an attacker to trigger a crash by sending an m=image line and
    zero port in a response to a T.38 re-invite initiated by Asterisk. This is a re-occurrence of the
    CVE-2019-15297 symptoms but not for exactly the same reason. The crash occurs because there is an append
    operation relative to the active topology, but this should instead be a replace operation.
    (CVE-2021-46837)

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

  - PJSIP is a free and open source multimedia communication library written in the C language. Versions 2.12
    and prior contain a denial-of-service vulnerability that affects PJSIP users that consume PJSIP's XML
    parsing in their apps. Users are advised to update. There are no known workarounds. (CVE-2022-24763)

  - PJSIP is a free and open source multimedia communication library written in C. Versions 2.12 and prior
    contain a stack buffer overflow vulnerability that affects PJSUA2 users or users that call the API
    `pjmedia_sdp_print(), pjmedia_sdp_media_print()`. Applications that do not use PJSUA2 and do not directly
    call `pjmedia_sdp_print()` or `pjmedia_sdp_media_print()` should not be affected. A patch is available on
    the `master` branch of the `pjsip/pjproject` GitHub repository. There are currently no known workarounds.
    (CVE-2022-24764)

  - PJSIP is a free and open source multimedia communication library written in C. PJSIP versions 2.12 and
    prior do not parse incoming RTCP feedback RPSI (Reference Picture Selection Indication) packet, but any
    app that directly uses pjmedia_rtcp_fb_parse_rpsi() will be affected. A patch is available in the `master`
    branch of the `pjsip/pjproject` GitHub repository. There are currently no known workarounds.
    (CVE-2022-24786)

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

  - An issue was discovered in Asterisk through 19.x. When using STIR/SHAKEN, it is possible to download files
    that are not certificates. These files could be much larger than what one would expect to download,
    leading to Resource Exhaustion. This is fixed in 16.25.2, 18.11.2, and 19.3.2. (CVE-2022-26498)

  - An SSRF issue was discovered in Asterisk through 19.x. When using STIR/SHAKEN, it's possible to send
    arbitrary requests (such as GET) to interfaces such as localhost by using the Identity header. This is
    fixed in 16.25.2, 18.11.2, and 19.3.2. (CVE-2022-26499)

  - An issue was discovered in Asterisk through 19.x and Certified Asterisk through 16.8-cert13. The func_odbc
    module provides possibly inadequate escaping functionality for backslash characters in SQL queries,
    resulting in user-provided data creating a broken SQL query or possibly a SQL injection. This is fixed in
    16.25.2, 18.11.2, and 19.3.2, and 16.8-cert14. (CVE-2022-26651)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1014998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/asterisk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3194");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43299");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43300");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43301");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43302");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43303");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-43845");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-46837");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21723");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23608");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24786");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24793");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26498");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26499");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26651");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/asterisk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the asterisk packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-26651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/19");

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

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'asterisk', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-config', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-dahdi', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-dev', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-doc', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-mobile', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-modules', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-mp3', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-mysql', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-ooh323', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-tests', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-voicemail', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-voicemail-imapstorage', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-voicemail-odbcstorage', 'reference': '1:16.28.0~dfsg-0+deb10u1'},
    {'release': '10.0', 'prefix': 'asterisk-vpb', 'reference': '1:16.28.0~dfsg-0+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'asterisk / asterisk-config / asterisk-dahdi / asterisk-dev / etc');
}
