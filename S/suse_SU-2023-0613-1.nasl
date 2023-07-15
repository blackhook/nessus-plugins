#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0613-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(172102);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2023-22745");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0613-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : tpm2-0-tss (SUSE-SU-2023:0613-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by a vulnerability as
referenced in the SUSE-SU-2023:0613-1 advisory.

  - tpm2-tss is an open source software implementation of the Trusted Computing Group (TCG) Trusted Platform
    Module (TPM) 2 Software Stack (TSS2). In affected versions `Tss2_RC_SetHandler` and `Tss2_RC_Decode` both
    index into `layer_handler` with an 8 bit layer number, but the array only has
    `TPM2_ERROR_TSS2_RC_LAYER_COUNT` entries, so trying to add a handler for higher-numbered layers or decode
    a response code with such a layer number reads/writes past the end of the buffer. This Buffer overrun,
    could result in arbitrary code execution. An example attack would be a MiTM bus attack that returns
    0xFFFFFFFF for the RC. Given the common use case of TPM modules an attacker must have local access to the
    target machine with local system privileges which allows access to the TPM system. Usually TPM access
    requires administrative privilege. (CVE-2023-22745)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207325");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-March/013966.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2860296c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-22745");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-esys0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-fapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-mu0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-rc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-sys0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-tcti-device0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-tcti-mssim0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtss2-tctildr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tpm2-0-tss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tpm2-0-tss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libtss2-esys0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-fapi0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-mu0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-rc0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-sys0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-tcti-device0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-tcti-mssim0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-tctildr0-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'tpm2-0-tss-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'tpm2-0-tss-devel-2.4.5-150300.3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3']},
    {'reference':'libtss2-fapi0-2.4.5-150300.3.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libtss2-sys0-2.4.5-150300.3.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libtss2-sys0-32bit-2.4.5-150300.3.6.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libtss2-esys0 / libtss2-fapi0 / libtss2-mu0 / libtss2-rc0 / etc');
}
