#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0169-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157104);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id(
    "CVE-2021-4083",
    "CVE-2021-4135",
    "CVE-2021-4149",
    "CVE-2021-4197",
    "CVE-2021-4202",
    "CVE-2021-45485",
    "CVE-2021-45486",
    "CVE-2021-46283",
    "CVE-2022-0185",
    "CVE-2022-0322"
  );

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2022:0169-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0169-1 advisory.

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - In the IPv6 implementation in the Linux kernel before 5.13.3, net/ipv6/output_core.c has an information
    leak because of certain use of a hash table which, although big, doesn't properly consider that IPv6-based
    attackers can typically choose among many IPv6 source addresses. (CVE-2021-45485)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

  - nf_tables_newset in net/netfilter/nf_tables_api.c in the Linux kernel before 5.12.13 allows local users to
    cause a denial of service (NULL pointer dereference and general protection fault) because of the missing
    initialization for nft_set_elem_expr_alloc. A local user can set a netfilter table expression in their own
    namespace. (CVE-2021-46283)

  - kernel: fs_context: heap overflow in legacy parameter handling (CVE-2022-0185)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1065729");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1156395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167773");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176774");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177437");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190256");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191271");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191929");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192931");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193255");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193328");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194027");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194094");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194493");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194586");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194587");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194589");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194985");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/S44U3IKMS3KZS626YQ5ZYDHA2HLKQNER/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27dcb678");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45485");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-46283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0185");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0322");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0185");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

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

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cluster-md-kmp-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dlm-kmp-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'gfs2-kmp-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-devel-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-extra-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-livepatch-devel-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-azure-optional-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-azure-5.3.18-150300.38.37.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-source-azure-5.3.18-150300.38.37.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-syms-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kselftests-kmp-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-kmp-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'reiserfs-kmp-azure-5.3.18-150300.38.37.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
