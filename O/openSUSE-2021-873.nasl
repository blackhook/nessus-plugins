#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:0873-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151080);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2021-29155", "CVE-2021-29650");

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2021:0873-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:0873-1 advisory.

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
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/THW3Z3CCX5HRFD2KJ3A4TDO27FGBEKNN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec9148fd");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-rt_debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'cluster-md-kmp-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cluster-md-kmp-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-rt-5.3.18-lp152.3.11.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-extra-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt_debug-devel-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt_debug-extra-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-rt-5.3.18-lp152.3.11.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-rt-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-rt_debug-5.3.18-lp152.3.11.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / cluster-md-kmp-rt_debug / dlm-kmp-rt / etc');
}
