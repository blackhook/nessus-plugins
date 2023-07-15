#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3800-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166692);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2022-3155",
    "CVE-2022-3266",
    "CVE-2022-39236",
    "CVE-2022-39249",
    "CVE-2022-39250",
    "CVE-2022-39251",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40962"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3800-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : MozillaThunderbird (SUSE-SU-2022:3800-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3800-1 advisory.

  - When saving or opening an email attachment on macOS, Thunderbird did not set attribute
    com.apple.quarantine on the received file. If the received file was an application and the user attempted
    to open it, then the application was started immediately without asking the user to confirm. This
    vulnerability affects Thunderbird < 102.3. (CVE-2022-3155)

  - An out-of-bounds read can occur when decoding H264 video. This results in a potentially exploitable crash.
    This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105. (CVE-2022-3266)

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

  - When injecting an HTML base element, some requests would ignore the CSP's base-uri settings and accept the
    injected element's base instead. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and
    Firefox < 105. (CVE-2022-40956)

  - Inconsistent data in instruction and data cache when creating wasm code could lead to a potentially
    exploitable crash.<br>*This bug only affects Firefox on ARM64 platforms.*. This vulnerability affects
    Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105. (CVE-2022-40957)

  - By injecting a cookie with certain special characters, an attacker on a shared subdomain which is not a
    secure context could set and thus overwrite cookies from a secure context, leading to session fixation and
    other attacks. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and Firefox < 105.
    (CVE-2022-40958)

  - During iframe navigation, certain pages did not have their FeaturePolicy fully initialized leading to a
    bypass that leaked device permissions into untrusted subdocuments. This vulnerability affects Firefox ESR
    < 102.3, Thunderbird < 102.3, and Firefox < 105. (CVE-2022-40959)

  - Concurrent use of the URL parser with non-UTF-8 data was not thread-safe. This could lead to a use-after-
    free causing a potentially exploitable crash. This vulnerability affects Firefox ESR < 102.3, Thunderbird
    < 102.3, and Firefox < 105. (CVE-2022-40960)

  - Mozilla developers Nika Layzell, Timothy Nikkel, Sebastian Hengst, Andreas Pehrson, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 102.3, Thunderbird < 102.3, and
    Firefox < 105. (CVE-2022-40962)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204421");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012724.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a02e7002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3266");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39236");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39249");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-39251");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40956");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40957");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40958");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40959");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40960");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-40962");
  script_set_attribute(attribute:"solution", value:
"Update the affected MozillaThunderbird, MozillaThunderbird-translations-common and / or MozillaThunderbird-translations-
other packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40962");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'sle-we-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'s390x', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'sle-we-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'MozillaThunderbird-102.4.0-150200.8.85.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaThunderbird-translations-common-102.4.0-150200.8.85.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'MozillaThunderbird-translations-other-102.4.0-150200.8.85.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'MozillaThunderbird / MozillaThunderbird-translations-common / etc');
}
