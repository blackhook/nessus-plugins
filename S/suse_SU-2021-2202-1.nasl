#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2202-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151200);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/09");

  script_cve_id(
    "CVE-2020-26558",
    "CVE-2020-36385",
    "CVE-2020-36386",
    "CVE-2021-0129"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2202-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:2202-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:2202-1 advisory.

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - An issue was discovered in the Linux kernel before 5.8.1. net/bluetooth/hci_event.c has a slab out-of-
    bounds read in hci_extended_inquiry_result_evt, aka CID-51c19bf3d5cf. (CVE-2020-36386)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185570");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186672");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186956");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186960");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186962");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186963");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186970");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186972");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186980");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186982");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186983");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186986");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186992");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186996");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187039");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187069");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187143");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187334");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187357");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187711");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/009101.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5af81e13");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26558");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36386");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0129");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'kernel-azure-5.3.18-38.8.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.3'},
    {'reference':'kernel-azure-devel-5.3.18-38.8.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.3'},
    {'reference':'kernel-devel-azure-5.3.18-38.8.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.3'},
    {'reference':'kernel-source-azure-5.3.18-38.8.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.3'},
    {'reference':'kernel-syms-azure-5.3.18-38.8.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-devel / kernel-devel-azure / etc');
}
