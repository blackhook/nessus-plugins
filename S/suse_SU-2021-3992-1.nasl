#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3992-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156009);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-0941",
    "CVE-2021-20322",
    "CVE-2021-31916",
    "CVE-2021-34981"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3992-1");

  script_name(english:"SUSE SLES12 Security Update : the Linux RT Kernel (SUSE-SU-2021:3992-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:3992-1 advisory.

  - In bpf_skb_change_head of filter.c, there is a possible out of bounds read due to a use after free. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-154177719References:
    Upstream kernel (CVE-2021-0941)

  - A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux
    kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source
    port randomization are indirectly affected as well. (CVE-2021-20322)

  - An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-
    device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or
    a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-31916)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1114648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190317");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192273");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192753");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192802");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192906");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192987");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009877.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3948be02");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-31916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-34981");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0941");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-20322");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
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
    {'reference':'cluster-md-kmp-rt-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'dlm-kmp-rt-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'gfs2-kmp-rt-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-devel-rt-4.12.14-10.70.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-rt-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-rt-base-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-rt-devel-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-rt_debug-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-source-rt-4.12.14-10.70.2', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'kernel-syms-rt-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.70.2', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SUSE-Linux-Enterprise-RT-release-12.5'}
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
