#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0270-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157302);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2021-4028", "CVE-2021-42739", "CVE-2022-0185");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0270-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (Live Patch 6 for SLE 15 SP3) (SUSE-SU-2022:0270-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0270-1 advisory.

  - A flaw in the Linux kernel's implementation of RDMA communications manager listener code allowed an
    attacker with local access to setup a socket to listen on a high port allowing for a list element to be
    used after free. Given the ability to execute code, a local attacker could leverage this use-after-free to
    crash the system or possibly escalate privileges on the system. (CVE-2021-4028)

  - A heap-based buffer overflow flaw was found in the Linux kernel FireDTV media card driver, where the user
    calls the CA_SEND_MSG ioctl. This flaw allows a local user of the host machine to crash the system or
    escalate privileges on the system. The highest threat from this vulnerability is to confidentiality,
    integrity, as well as system availability. (CVE-2021-42739)

  - A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem
    Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in
    case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local
    user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to
    legacy handling) could use this flaw to escalate their privileges on the system. (CVE-2022-0185)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194737");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-February/010156.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e2564ab");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4028");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0185");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel-livepatch-5_3_18-59_24-default and / or kernel-livepatch-5_3_18-59_27-default packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0185");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_24-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-59_27-default");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var kernel_live_checks = [
  {
    'kernels': {
      '5.3.18-59.24-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_24-default-4-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
        ]
      },
      '5.3.18-59.27-default': {
        'pkgs': [
          {'reference':'kernel-livepatch-5_3_18-59_27-default-4-150300.2.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-livepatch-5_3_18-59_24-default / etc');
}
