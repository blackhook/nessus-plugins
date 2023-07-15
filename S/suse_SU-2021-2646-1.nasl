#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:2646-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152479);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-3659",
    "CVE-2021-21781",
    "CVE-2021-22543",
    "CVE-2021-37576"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:2646-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2021:2646-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:2646-1 advisory.

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - A NULL pointer dereference flaw was found in the Linux kernel's IEEE 802.15.4 wireless networking
    subsystem in the way the user closes the LR-WPAN connection. This flaw allows a local user to crash the
    system. The highest threat from this vulnerability is to system availability. (CVE-2021-3659)

  - An information disclosure vulnerability exists in the ARM SIGPAGE functionality of Linux Kernel v5.4.66
    and v5.4.54. The latest version (5.11-rc4) seems to still be vulnerable. A userland application can read
    the contents of the sigpage, which can leak kernel memory contents. An attacker can read a process's
    memory at a specific offset to trigger this vulnerability. This was fixed in kernel releases: 4.14.222
    4.19.177 5.4.99 5.10.17 5.11 (CVE-2021-21781)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1085224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1094840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1113295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180092");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186194");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186206");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188101");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188746");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188771");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188777");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188838");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188973");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-August/009277.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5249191e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21781");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22543");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-azure-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-azure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kernel-azure-5.3.18-18.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-azure-devel-5.3.18-18.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-devel-azure-5.3.18-18.61.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-source-azure-5.3.18-18.61.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'},
    {'reference':'kernel-syms-azure-5.3.18-18.61.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-public-cloud-release-15.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-azure / kernel-azure-devel / kernel-devel-azure / etc');
}
