#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:2401. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(176931);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/08");

  script_cve_id(
    "CVE-2023-1872",
    "CVE-2023-1989",
    "CVE-2023-2162",
    "CVE-2023-23454"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:2401");

  script_name(english:"SUSE SLES15 Security Update : kernel (Live Patch 31 for SLE 15 SP3) (SUSE-SU-2023:2401)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2023:2401 advisory.

  - A use-after-free vulnerability in the Linux Kernel io_uring system can be exploited to achieve local
    privilege escalation. The io_file_get_fixed function lacks the presence of ctx->uring_lock which can lead
    to a Use-After-Free vulnerability due a race condition with fixed files getting unregistered. We recommend
    upgrading past commit da24142b1ef9fd5d36b76e36bab328a5b27523e8. (CVE-2023-1872)

  - A use-after-free flaw was found in btsdio_remove in drivers\bluetooth\btsdio.c in the Linux Kernel. In
    this flaw, a call to btsdio_remove with an unfinished job, may cause a race problem leading to a UAF on
    hdev devices. (CVE-2023-1989)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207188");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210662");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2023-June/029744.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1989");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2162");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-23454");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-5_3_18-150200_24_148-default and / or kernel-livepatch-5_3_18-150300_59_118-default
packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1989");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150200_24_148-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_118-default");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

var uname_r = get_kb_item("Host/uname-r");
if (empty_or_null(uname_r)) audit(AUDIT_UNKNOWN_APP_VER, "kernel");

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '5.3.18-150200.24.148-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150200_24_148-default-2-150200.2.3', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.2']}
        ]
      },
      '5.3.18-150300.59.118-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-150300_59_118-default-2-150300.2.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      }
    }
  }
];

var ltss_caveat_required = FALSE;
var flag = 0;
var kernel_affected = FALSE;
foreach var kernel_array ( kernel_live_checks ) {
  var kpatch_details = kernel_array['kernels'][uname_r];
  if (empty_or_null(kpatch_details)) continue;
  kernel_affected = TRUE;
  foreach var package_array ( kpatch_details['pkgs'] ) {
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
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

# No kpatch details found for the running kernel version
if (!kernel_affected) audit(AUDIT_INST_VER_NOT_VULN, 'kernel', uname_r);

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-5_3_18-150200_24_148-default / etc');
}
