##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1853-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(161651);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2015-8041",
    "CVE-2017-13077",
    "CVE-2017-13078",
    "CVE-2017-13079",
    "CVE-2017-13080",
    "CVE-2017-13081",
    "CVE-2017-13082",
    "CVE-2017-13086",
    "CVE-2017-13087",
    "CVE-2017-13088",
    "CVE-2018-14526",
    "CVE-2019-9494",
    "CVE-2019-9495",
    "CVE-2019-9497",
    "CVE-2019-9498",
    "CVE-2019-9499",
    "CVE-2019-11555",
    "CVE-2019-13377",
    "CVE-2022-23303",
    "CVE-2022-23304"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1853-1");

  script_name(english:"SUSE SLES12 Security Update : wpa_supplicant (SUSE-SU-2022:1853-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:1853-1 advisory.

  - Multiple integer overflows in the NDEF record parser in hostapd before 2.5 and wpa_supplicant before 2.5
    allow remote attackers to cause a denial of service (process crash or infinite loop) via a large payload
    length field value in an (1) WPS or (2) P2P NFC NDEF record, which triggers an out-of-bounds read.
    (CVE-2015-8041)

  - Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Pairwise Transient Key (PTK) Temporal
    Key (TK) during the four-way handshake, allowing an attacker within radio range to replay, decrypt, or
    spoof frames. (CVE-2017-13077)

  - Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the
    four-way handshake, allowing an attacker within radio range to replay frames from access points to
    clients. (CVE-2017-13078)

  - Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity
    Group Temporal Key (IGTK) during the four-way handshake, allowing an attacker within radio range to spoof
    frames from access points to clients. (CVE-2017-13079)

  - Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Group Temporal Key (GTK) during the
    group key handshake, allowing an attacker within radio range to replay frames from access points to
    clients. (CVE-2017-13080)

  - Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11w allows reinstallation of the Integrity
    Group Temporal Key (IGTK) during the group key handshake, allowing an attacker within radio range to spoof
    frames from access points to clients. (CVE-2017-13081)

  - Wi-Fi Protected Access (WPA and WPA2) that supports IEEE 802.11r allows reinstallation of the Pairwise
    Transient Key (PTK) Temporal Key (TK) during the fast BSS transmission (FT) handshake, allowing an
    attacker within radio range to replay, decrypt, or spoof frames. (CVE-2017-13082)

  - Wi-Fi Protected Access (WPA and WPA2) allows reinstallation of the Tunneled Direct-Link Setup (TDLS) Peer
    Key (TPK) during the TDLS handshake, allowing an attacker within radio range to replay, decrypt, or spoof
    frames. (CVE-2017-13086)

  - Wi-Fi Protected Access (WPA and WPA2) that support 802.11v allows reinstallation of the Group Temporal Key
    (GTK) when processing a Wireless Network Management (WNM) Sleep Mode Response frame, allowing an attacker
    within radio range to replay frames from access points to clients. (CVE-2017-13087)

  - Wi-Fi Protected Access (WPA and WPA2) that support 802.11v allows reinstallation of the Integrity Group
    Temporal Key (IGTK) when processing a Wireless Network Management (WNM) Sleep Mode Response frame,
    allowing an attacker within radio range to replay frames from access points to clients. (CVE-2017-13088)

  - An issue was discovered in rsn_supp/wpa.c in wpa_supplicant 2.0 through 2.6. Under certain conditions, the
    integrity of EAPOL-Key messages is not checked, leading to a decryption oracle. An attacker within range
    of the Access Point and client can abuse the vulnerability to recover sensitive information.
    (CVE-2018-14526)

  - The EAP-pwd implementation in hostapd (EAP server) before 2.8 and wpa_supplicant (EAP peer) before 2.8
    does not validate fragmentation reassembly state properly for a case where an unexpected fragment could be
    received. This could result in process termination due to a NULL pointer dereference (denial of service).
    This affects eap_server/eap_server_pwd.c and eap_peer/eap_pwd.c. (CVE-2019-11555)

  - The implementations of SAE and EAP-pwd in hostapd and wpa_supplicant 2.x through 2.8 are vulnerable to
    side-channel attacks as a result of observable timing differences and cache access patterns when Brainpool
    curves are used. An attacker may be able to gain leaked information from a side-channel attack that can be
    used for full password recovery. (CVE-2019-13377)

  - The implementations of SAE in hostapd and wpa_supplicant are vulnerable to side channel attacks as a
    result of observable timing differences and cache access patterns. An attacker may be able to gain leaked
    information from a side channel attack that can be used for full password recovery. Both hostapd with SAE
    support and wpa_supplicant with SAE support prior to and including version 2.7 are affected.
    (CVE-2019-9494)

  - The implementations of EAP-PWD in hostapd and wpa_supplicant are vulnerable to side-channel attacks as a
    result of cache access patterns. All versions of hostapd and wpa_supplicant with EAP-PWD support are
    vulnerable. The ability to install and execute applications is necessary for a successful attack. Memory
    access patterns are visible in a shared cache. Weak passwords may be cracked. Versions of
    hostapd/wpa_supplicant 2.7 and newer, are not vulnerable to the timing attack described in CVE-2019-9494.
    Both hostapd with EAP-pwd support and wpa_supplicant with EAP-pwd support prior to and including version
    2.7 are affected. (CVE-2019-9495)

  - The implementations of EAP-PWD in hostapd EAP Server and wpa_supplicant EAP Peer do not validate the
    scalar and element values in EAP-pwd-Commit. This vulnerability may allow an attacker to complete EAP-PWD
    authentication without knowing the password. However, unless the crypto library does not implement
    additional checks for the EC point, the attacker will not be able to derive the session key or complete
    the key exchange. Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including
    version 2.4 are affected. Both hostapd with EAP-pwd support and wpa_supplicant with EAP-pwd support prior
    to and including version 2.7 are affected. (CVE-2019-9497)

  - The implementations of EAP-PWD in hostapd EAP Server, when built against a crypto library missing explicit
    validation on imported elements, do not validate the scalar and element values in EAP-pwd-Commit. An
    attacker may be able to use invalid scalar/element values to complete authentication, gaining session key
    and network access without needing or learning the password. Both hostapd with SAE support and
    wpa_supplicant with SAE support prior to and including version 2.4 are affected. Both hostapd with EAP-pwd
    support and wpa_supplicant with EAP-pwd support prior to and including version 2.7 are affected.
    (CVE-2019-9498)

  - The implementations of EAP-PWD in wpa_supplicant EAP Peer, when built against a crypto library missing
    explicit validation on imported elements, do not validate the scalar and element values in EAP-pwd-Commit.
    An attacker may complete authentication, session key and control of the data connection with a client.
    Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.4 are
    affected. Both hostapd with EAP-pwd support and wpa_supplicant with EAP-pwd support prior to and including
    version 2.7 are affected. (CVE-2019-9499)

  - The implementations of SAE in hostapd before 2.10 and wpa_supplicant before 2.10 are vulnerable to side
    channel attacks as a result of cache access patterns. NOTE: this issue exists because of an incomplete fix
    for CVE-2019-9494. (CVE-2022-23303)

  - The implementations of EAP-pwd in hostapd before 2.10 and wpa_supplicant before 2.10 are vulnerable to
    side-channel attacks as a result of cache access patterns. NOTE: this issue exists because of an
    incomplete fix for CVE-2019-9495. (CVE-2022-23304)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131868");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131872");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1131874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1133640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144443");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156920");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1165266");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1166933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194733");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-May/011164.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c23a76d0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-8041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13078");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13079");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13080");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13081");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13082");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-13088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14526");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13377");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9494");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9495");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9497");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9498");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9499");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23303");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23304");
  script_set_attribute(attribute:"solution", value:
"Update the affected wpa_supplicant package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'wpa_supplicant-2.9-15.22.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.3', 'sles-bcl-release-12.3']},
    {'reference':'wpa_supplicant-2.9-15.22.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.4']},
    {'reference':'wpa_supplicant-2.9-15.22.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-bcl-release-12.2']},
    {'reference':'wpa_supplicant-2.9-15.22.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.3']},
    {'reference':'wpa_supplicant-2.9-15.22.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.4']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wpa_supplicant');
}
