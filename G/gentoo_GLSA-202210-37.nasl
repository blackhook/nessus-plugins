#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202210-37.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(166740);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/31");

  script_cve_id(
    "CVE-2021-32686",
    "CVE-2021-37706",
    "CVE-2021-41141",
    "CVE-2021-43804",
    "CVE-2021-43845",
    "CVE-2022-21722",
    "CVE-2022-21723",
    "CVE-2022-23608",
    "CVE-2022-24754",
    "CVE-2022-24763",
    "CVE-2022-24764",
    "CVE-2022-24786",
    "CVE-2022-24792",
    "CVE-2022-24793",
    "CVE-2022-31031",
    "CVE-2022-39244",
    "CVE-2022-39269"
  );

  script_name(english:"GLSA-202210-37 : PJSIP: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202210-37 (PJSIP: Multiple Vulnerabilities)

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

  - PJSIP is a free and open source multimedia communication library written in C language implementing
    standard based protocols such as SIP, SDP, RTP, STUN, TURN, and ICE. In versions prior to and including
    2.12.1 a stack buffer overflow vulnerability affects PJSIP users that use STUN in their applications,
    either by: setting a STUN server in their account/media config in PJSUA/PJSUA2 level, or directly using
    `pjlib-util/stun_simple` API. A patch is available in commit 450baca which should be included in the next
    release. There are no known workarounds for this issue. (CVE-2022-31031)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202210-37");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803614");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829894");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=875863");
  script_set_attribute(attribute:"solution", value:
"All PJSIP users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-libs/pjproject-2.12.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37706");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39244");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:pjproject");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-libs/pjproject',
    'unaffected' : make_list("ge 2.12.1", "lt 2.0.0"),
    'vulnerable' : make_list("lt 2.12.1")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'PJSIP');
}
