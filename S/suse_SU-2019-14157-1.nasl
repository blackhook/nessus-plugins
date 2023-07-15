#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14157-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150618);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2015-9289",
    "CVE-2018-20855",
    "CVE-2019-1125",
    "CVE-2019-11810",
    "CVE-2019-13631",
    "CVE-2019-14283",
    "CVE-2019-14284"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14157-1");
  script_xref(name:"IAVA", value:"2019-A-0290-S");
  script_xref(name:"IAVA", value:"2019-A-0293-S");
  script_xref(name:"IAVA", value:"2019-A-0285-S");
  script_xref(name:"IAVA", value:"2019-A-0284-S");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2019:14157-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14157-1 advisory.

  - In the Linux kernel before 4.1.4, a buffer overflow occurs when checking userspace params in
    drivers/media/dvb-frontends/cx24116.c. The maximum size for a DiSEqC command is 6, according to the
    userspace API. However, the code allows larger values such as 23. (CVE-2015-9289)

  - An issue was discovered in the Linux kernel before 4.18.7. In create_qp_common in
    drivers/infiniband/hw/mlx5/qp.c, mlx5_ib_create_qp_resp was never initialized, resulting in a leak of
    stack memory to userspace. (CVE-2018-20855)

  - An information disclosure vulnerability exists when certain central processing units (CPU) speculatively
    access memory, aka 'Windows Kernel Information Disclosure Vulnerability'. This CVE ID is unique from
    CVE-2019-1071, CVE-2019-1073. (CVE-2019-1125)

  - An issue was discovered in the Linux kernel before 5.0.7. A NULL pointer dereference can occur when
    megasas_create_frame_pool() fails in megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c.
    This causes a Denial of Service, related to a use-after-free. (CVE-2019-11810)

  - In parse_hid_report_descriptor in drivers/input/tablet/gtco.c in the Linux kernel through 5.2.1, a
    malicious USB device can send an HID report that triggers an out-of-bounds write during generation of
    debugging messages. (CVE-2019-13631)

  - In the Linux kernel before 5.2.3, set_geometry in drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by
    default. (CVE-2019-14283)

  - In the Linux kernel before 5.2.3, drivers/block/floppy.c allows a denial of service by setup_format_params
    division-by-zero. Two consecutive ioctls can trigger the bug: the first one should set the drive geometry
    with .sect and .rate values that make F_SECT_PER_TRACK be zero. Next, the floppy format operation should
    be called. It can be triggered by an unprivileged local user even when a floppy disk has not been
    inserted. NOTE: QEMU creates the floppy device by default. (CVE-2019-14284)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1134390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1134399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1138744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1139358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141401");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141402");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141453");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1141454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142023");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143179");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143191");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-August/005859.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?542ab5fc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-9289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-20855");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11810");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-13631");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14283");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14284");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-9289");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14283");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'kernel-default-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.101', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kernel-default-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.101', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.101', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.101', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.101', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-default / kernel-default-base / kernel-default-devel / etc');
}
