#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1915-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150476);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id("CVE-2021-29155", "CVE-2021-29650");
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1915-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:1915-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:1915-1 advisory.

  - An issue was discovered in the Linux kernel through 5.11.x. kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer
    arithmetic operations, the pointer modification performed by the first operation is not correctly
    accounted for when restricting subsequent operations. (CVE-2021-29155)

  - An issue was discovered in the Linux kernel before 5.11.11. The netfilter subsystem allows attackers to
    cause a denial of service (panic) because net/netfilter/x_tables.c and include/linux/netfilter/x_tables.h
    lack a full memory barrier upon the assignment of a new table value, aka CID-175e476b8cdf.
    (CVE-2021-29650)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1043990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1055117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152457");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167260");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174416");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179851");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183063");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184485");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184724");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184730");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184736");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184737");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184742");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184760");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184984");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185041");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185113");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185233");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185587");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/008971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f557a114");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-29650");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29155");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'dlm-kmp-rt-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'gfs2-kmp-rt-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-devel-rt-5.3.18-8.10', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-rt-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-rt-devel-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-rt_debug-devel-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-source-rt-5.3.18-8.10', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'kernel-syms-rt-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'},
    {'reference':'ocfs2-kmp-rt-5.3.18-8.10', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-rt-release-15.3'}
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
      severity   : SECURITY_NOTE,
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
