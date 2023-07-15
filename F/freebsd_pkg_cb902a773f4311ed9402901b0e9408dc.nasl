#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(165517);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-39236",
    "CVE-2022-39249",
    "CVE-2022-39250",
    "CVE-2022-39251"
  );

  script_name(english:"FreeBSD : Matrix clients -- several vulnerabilities (cb902a77-3f43-11ed-9402-901b0e9408dc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the cb902a77-3f43-11ed-9402-901b0e9408dc advisory.

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Prior to version 19.7.0, an attacker
    cooperating with a malicious homeserver can construct messages that legitimately appear to have come from
    another person, without any indication such as a grey shield. Additionally, a sophisticated attacker
    cooperating with a malicious homeserver could employ this vulnerability to perform a targeted attack in
    order to send fake to-device messages appearing to originate from another user. This can allow, for
    example, to inject the key backup secret during a self-verification, to make a targeted device start using
    a malicious key backup spoofed by the homeserver. These attacks are possible due to a protocol confusion
    vulnerability that accepts to-device messages encrypted with Megolm instead of Olm. Starting with version
    19.7.0, matrix-js-sdk has been modified to only accept Olm-encrypted to-device messages. Out of caution,
    several other checks have been audited or added. This attack requires coordination between a malicious
    home server and an attacker, so those who trust their home servers do not need a workaround.
    (CVE-2022-39251)

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Starting with version 17.1.0-rc.1,
    improperly formed beacon events can disrupt or impede the matrix-js-sdk from functioning properly,
    potentially impacting the consumer's ability to process data safely. Note that the matrix-js-sdk can
    appear to be operating normally but be excluding or corrupting runtime data presented to the consumer.
    This is patched in matrix-js-sdk v19.7.0. Redacting applicable events, waiting for the sync processor to
    store data, and restarting the client are possible workarounds. Alternatively, redacting the applicable
    events and clearing all storage will fix the further perceived issues. Downgrading to an unaffected
    version, noting that such a version may be subject to other vulnerabilities, will additionally resolve the
    issue. (CVE-2022-39236)

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Prior to version 19.7.0, an attacker
    cooperating with a malicious homeserver can construct messages appearing to have come from another person.
    Such messages will be marked with a grey shield on some platforms, but this may be missing in others. This
    attack is possible due to the matrix-js-sdk implementing a too permissive key forwarding strategy on the
    receiving end. Starting with version 19.7.0, the default policy for accepting key forwards has been made
    more strict in the matrix-js-sdk. matrix-js-sdk will now only accept forwarded keys in response to
    previously issued requests and only from own, verified devices. The SDK now sets a `trusted` flag on the
    decrypted message upon decryption, based on whether the key used to decrypt the message was received from
    a trusted source. Clients need to ensure that messages decrypted with a key with `trusted = false` are
    decorated appropriately, for example, by showing a warning for such messages. This attack requires
    coordination between a malicious homeserver and an attacker, and those who trust your homeservers do not
    need a workaround. (CVE-2022-39249)

  - Matrix JavaScript SDK is the Matrix Client-Server software development kit (SDK) for JavaScript. Prior to
    version 19.7.0, an attacker cooperating with a malicious homeserver could interfere with the verification
    flow between two users, injecting its own cross-signing user identity in place of one of the users'
    identities. This would lead to the other device trusting/verifying the user identity under the control of
    the homeserver instead of the intended one. The vulnerability is a bug in the matrix-js-sdk, caused by
    checking and signing user identities and devices in two separate steps, and inadequately fixing the keys
    to be signed between those steps. Even though the attack is partly made possible due to the design
    decision of treating cross-signing user identities as Matrix devices on the server side (with their device
    ID set to the public part of the user identity key), no other examined implementations were vulnerable.
    Starting with version 19.7.0, the matrix-js-sdk has been modified to double check that the key signed is
    the one that was verified instead of just referencing the key by ID. An additional check has been made to
    report an error when one of the device ID matches a cross-signing key. As this attack requires
    coordination between a malicious homeserver and an attacker, those who trust their homeservers do not need
    a particular workaround. (CVE-2022-39250)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://matrix.org/blog/2022/09/28/upgrade-now-to-address-encryption-vulns-in-matrix-sdks-and-clients
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26501212");
  # https://vuxml.freebsd.org/freebsd/cb902a77-3f43-11ed-9402-901b0e9408dc.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31bae0dd");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39251");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cinny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:element-web");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'cinny<2.2.1',
    'element-web<1.11.7'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
