#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:2645-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152459);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/11");

  script_cve_id(
    "CVE-2021-3609",
    "CVE-2021-3612",
    "CVE-2021-3659",
    "CVE-2021-21781",
    "CVE-2021-22543",
    "CVE-2021-35039",
    "CVE-2021-37576"
  );

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2021:2645-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:2645-1 advisory.

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - kernel/module.c in the Linux kernel before 5.12.14 mishandles Signature Verification, aka
    CID-0c18f29aae7c. Without CONFIG_MODULE_SIG, verification that a kernel module is signed, for loading via
    init_module, does not occur for a module.sig_enforce=1 command-line argument. (CVE-2021-35039)

  - kernel: race condition in net/can/bcm.c leads to local privilege escalation (CVE-2021-3609)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1085224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1094840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1113295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1170511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180814");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185308");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188121");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188176");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188268");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188269");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188720");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188973");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2WMUIJQF7RUSXDRXECLPMVDE6YOS5WIN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?217b5a35");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3659");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37576");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cluster-md-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dlm-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gfs2-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-azure-optional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kselftests-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocfs2-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:reiserfs-kmp-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'cluster-md-kmp-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-devel-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-extra-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-livepatch-devel-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-optional-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-azure-5.3.18-38.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-azure-5.3.18-38.17.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-azure-5.3.18-38.17.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-azure / dlm-kmp-azure / gfs2-kmp-azure / kernel-azure / etc');
}
