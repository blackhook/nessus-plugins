#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3658-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155303);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/28");

  script_cve_id(
    "CVE-2021-3542",
    "CVE-2021-3655",
    "CVE-2021-3715",
    "CVE-2021-3760",
    "CVE-2021-3772",
    "CVE-2021-3896",
    "CVE-2021-41864",
    "CVE-2021-42008",
    "CVE-2021-42252",
    "CVE-2021-42739",
    "CVE-2021-43056"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3658-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:3658-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3658-1 advisory.

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-42739. Reason: This candidate is a
    reservation duplicate of CVE-2021-42739. Notes: All CVE users should reference CVE-2021-42739 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2021-3542)

  - A vulnerability was found in the Linux kernel in versions prior to v5.14-rc1. Missing size validations on
    inbound SCTP packets may allow the kernel to read uninitialized memory. (CVE-2021-3655)

  - kernel: use-after-free in route4_change() in net/sched/cls_route.c (CVE-2021-3715)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-43389. Reason: This candidate is a
    reservation duplicate of CVE-2021-43389. Notes: All CVE users should reference CVE-2021-43389 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2021-3896)

  - prealloc_elems_and_freelist in kernel/bpf/stackmap.c in the Linux kernel through 5.14.9 allows
    unprivileged users to trigger an eBPF multiplication integer overflow with a resultant out-of-bounds
    write. (CVE-2021-41864)

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - An issue was discovered in aspeed_lpc_ctrl_mmap in drivers/soc/aspeed/aspeed-lpc-ctrl.c in the Linux
    kernel before 5.14.6. Local attackers able to access the Aspeed LPC control interface could overwrite
    memory in the kernel and potentially execute privileges, aka CID-b49a0e69a7b1. This occurs because a
    certain comparison uses values that are not memory sizes. (CVE-2021-42252)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

  - An issue was discovered in the Linux kernel for powerpc before 5.14.15. It allows a malicious KVM guest to
    crash the host, when the host is running on Power8, due to an arch/powerpc/kvm/book3s_hv_rmhandlers.S
    implementation bug in the handling of the SRR1 register values. (CVE-2021-43056)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1085030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191349");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191455");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191800");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192145");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-November/009719.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c078e277");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3760");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-41864");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42252");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43056");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'dlm-kmp-rt-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'gfs2-kmp-rt-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-devel-rt-5.3.18-57.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt-devel-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt_debug-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt_debug-devel-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-source-rt-5.3.18-57.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-syms-rt-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'ocfs2-kmp-rt-5.3.18-57.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
