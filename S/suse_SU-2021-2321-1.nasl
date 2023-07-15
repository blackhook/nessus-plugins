#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2321-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151649);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2019-25045",
    "CVE-2020-24588",
    "CVE-2020-26558",
    "CVE-2020-36386",
    "CVE-2021-0129",
    "CVE-2021-0512",
    "CVE-2021-0605",
    "CVE-2021-33624",
    "CVE-2021-34693"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2321-1");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2021:2321-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:2321-1 advisory.

  - An issue was discovered in the Linux kernel before 5.0.19. The XFRM subsystem has a use-after-free,
    related to an xfrm_state_fini panic, aka CID-dbb2483b2a46. (CVE-2019-25045)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - An issue was discovered in the Linux kernel before 5.8.1. net/bluetooth/hci_event.c has a slab out-of-
    bounds read in hci_extended_inquiry_result_evt, aka CID-51c19bf3d5cf. (CVE-2020-36386)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

  - In __hidinput_change_resolution_multipliers of hid-input.c, there is a possible out of bounds write due to
    a heap buffer overflow. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-173843328References: Upstream kernel (CVE-2021-0512)

  - In pfkey_dump of af_key.c, there is a possible out-of-bounds read due to a missing bounds check. This
    could lead to local information disclosure in the kernel with System execution privileges needed. User
    interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-110373476
    (CVE-2021-0605)

  - In kernel/bpf/verifier.c in the Linux kernel before 5.12.13, a branch can be mispredicted (e.g., because
    of type confusion) and consequently an unprivileged BPF program can read arbitrary memory locations via a
    side-channel attack, aka CID-9183671af6db. (CVE-2021-33624)

  - net/can/bcm.c in the Linux kernel through 5.12.10 allows local users to obtain sensitive information from
    kernel stack memory because parts of a data structure are uninitialized. (CVE-2021-34693)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1103991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1104353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1113994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1129770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1135481");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1136345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186520");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186527");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186532");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186538");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186541");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186551");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187411");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187833");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187972");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-July/009132.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e18542a4");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-25045");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0605");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34693");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36386");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-0512");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'kernel-azure-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-base-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-devel-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-devel-azure-4.12.14-16.62.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-source-azure-4.12.14-16.62.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-syms-azure-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'kernel-azure-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-azure-base-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-azure-devel-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-devel-azure-4.12.14-16.62.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-source-azure-4.12.14-16.62.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'kernel-syms-azure-4.12.14-16.62.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-base / kernel-azure-devel / etc');
}
