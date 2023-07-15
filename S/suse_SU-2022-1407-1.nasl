#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1407-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160222);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-45868",
    "CVE-2022-0850",
    "CVE-2022-0854",
    "CVE-2022-1011",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1055",
    "CVE-2022-1195",
    "CVE-2022-1198",
    "CVE-2022-1199",
    "CVE-2022-1205",
    "CVE-2022-27666",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1407-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:1407-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:1407-1 advisory.

  - In the Linux kernel before 5.15.3, fs/quota/quota_tree.c does not validate the block number in the quota
    tree (on disk). This can, for example, lead to a kernel/locking/rwsem.c use-after-free if there is a
    corrupted quota file. (CVE-2021-45868)

  - A memory leak flaw was found in the Linux kernel's DMA subsystem, in the way a user calls DMA_FROM_DEVICE.
    This flaw allows a local user to read random memory from the kernel space. (CVE-2022-0854)

  - A flaw use after free in the Linux kernel FUSE filesystem was found in the way user triggers write(). A
    local user could use this flaw to get some unauthorized access to some data from the FUSE filesystem and
    as result potentially privilege escalation too. (CVE-2022-1011)

  - A flaw was found in the Linux kernel in linux/net/netfilter/nf_tables_api.c of the netfilter subsystem.
    This flaw allows a local user to cause an out-of-bounds write issue. (CVE-2022-1015) (CVE-2022-1016)

  - A use-after-free exists in the Linux Kernel in tc_new_tfilter that could allow a local attacker to gain
    privilege escalation. The exploit requires unprivileged user namespaces. We recommend upgrading past
    commit 04c2a47ffb13c29778e2a14e414ad4cb5a5db4b5 (CVE-2022-1055)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28389)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175667");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195926");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197331");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197389");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197501");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197661");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197702");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197820");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197889");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1197894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198030");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198033");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198077");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0969113");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0850");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1055");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1195");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1199");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1205");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-27666");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28388");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28389");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28390");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1048");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmrt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


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
    {'reference':'cluster-md-kmp-rt-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'dlm-kmp-rt-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'gfs2-kmp-rt-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-devel-rt-5.3.18-150300.85.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt-devel-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-rt_debug-devel-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-source-rt-5.3.18-150300.85.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'kernel-syms-rt-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']},
    {'reference':'ocfs2-kmp-rt-5.3.18-150300.85.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.3', 'sle-module-rt-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
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
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
