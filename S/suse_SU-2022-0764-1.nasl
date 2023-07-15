#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0764-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159156);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/13");

  script_cve_id("CVE-2022-0001", "CVE-2022-0002", "CVE-2022-0847");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0764-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/16");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2022:0764-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0764-1 advisory.

  - Non-transparent sharing of branch predictor selectors between contexts in some Intel(R) Processors may
    allow an authorized user to potentially enable information disclosure via local access. (CVE-2022-0001)

  - Non-transparent sharing of branch predictor within a context in some Intel(R) Processors may allow an
    authorized user to potentially enable information disclosure via local access. (CVE-2022-0002)

  - A flaw was found in the way the flags member of the new pipe buffer structure was lacking proper
    initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus
    contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache
    backed by read only files and as such escalate their privileges on the system. (CVE-2022-0847)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196584");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010389.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f7ac8b9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0001");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0847");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Dirty Pipe Local Privilege Escalation via CVE-2022-0847');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
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
    {'reference':'cluster-md-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'dlm-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'gfs2-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-devel-rt-5.3.18-76.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-rt-devel-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-rt_debug-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-rt_debug-devel-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-source-rt-5.3.18-76.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'kernel-syms-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'ocfs2-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLE_RT-release-15.2'},
    {'reference':'cluster-md-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'dlm-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'gfs2-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-devel-rt-5.3.18-76.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt-devel-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt_debug-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-rt_debug-devel-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-source-rt-5.3.18-76.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'kernel-syms-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'},
    {'reference':'ocfs2-kmp-rt-5.3.18-76.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.2'}
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
