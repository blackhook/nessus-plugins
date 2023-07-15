#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2019:14199-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150593);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/21");

  script_cve_id(
    "CVE-2019-12067",
    "CVE-2019-12068",
    "CVE-2019-12155",
    "CVE-2019-14378",
    "CVE-2019-15890",
    "CVE-2019-17340",
    "CVE-2019-17341",
    "CVE-2019-17342",
    "CVE-2019-17343",
    "CVE-2019-17344",
    "CVE-2019-17346",
    "CVE-2019-17347",
    "CVE-2019-17348"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2019:14199-1");
  script_xref(name:"IAVB", value:"2019-B-0079-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2019:14199-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2019:14199-1 advisory.

  - The ahci_commit_buf function in ide/ahci.c in QEMU allows attackers to cause a denial of service (NULL
    dereference) when the command header 'ad->cur_cmd' is null. (CVE-2019-12067)

  - In QEMU 1:4.1-1, 1:2.1+dfsg-12+deb8u6, 1:2.8+dfsg-6+deb9u8, 1:3.1+dfsg-8~deb10u1, 1:3.1+dfsg-8+deb10u2,
    and 1:2.1+dfsg-12+deb8u12 (fixed), when executing script in lsi_execute_script(), the LSI scsi adapter
    emulator advances 's->dsp' index to read next opcode. This can lead to an infinite loop if the next opcode
    is empty. Move the existing loop exit after 10k iterations so that it covers no-op opcodes as well.
    (CVE-2019-12068)

  - interface_release_resource in hw/display/qxl.c in QEMU 3.1.x through 4.0.0 has a NULL pointer dereference.
    (CVE-2019-12155)

  - ip_reass in ip_input.c in libslirp 4.0.0 has a heap-based buffer overflow via a large packet because it
    mishandles a case involving the first fragment. (CVE-2019-14378)

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a use-after-free in ip_reass in ip_input.c. (CVE-2019-15890)

  - An issue was discovered in Xen through 4.11.x allowing x86 guest OS users to cause a denial of service or
    gain privileges because grant-table transfer requests are mishandled. (CVE-2019-17340)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    or gain privileges by leveraging a page-writability race condition during addition of a passed-through PCI
    device. (CVE-2019-17341)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    or gain privileges by leveraging a race condition that arose when XENMEM_exchange was introduced.
    (CVE-2019-17342)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    or gain privileges by leveraging incorrect use of the HVM physmap concept for PV domains. (CVE-2019-17343)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    by leveraging a long-running operation that exists to support restartability of PTE updates.
    (CVE-2019-17344)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    or gain privileges because of an incompatibility between Process Context Identifiers (PCID) and TLB
    flushes. (CVE-2019-17346)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    or gain privileges because a guest can manipulate its virtualised %cr4 in a way that is incompatible with
    Linux (and possibly other guest kernels). (CVE-2019-17347)

  - An issue was discovered in Xen through 4.11.x allowing x86 PV guest OS users to cause a denial of service
    because of an incompatibility between Process Context Identifiers (PCID) and shadow-pagetable switching.
    (CVE-2019-17348)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126141");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126198");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1127400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1135905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1145652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1146874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149813");
  # https://lists.suse.com/pipermail/sle-security-updates/2019-October/006052.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f7b624c2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14378");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17340");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17341");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17342");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17346");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17347");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17348");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17346");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

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
    {'reference':'xen-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_40_3.0.101_108.101-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_40_3.0.101_108.101-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_40_3.0.101_108.101-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_40-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_40-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_40_3.0.101_108.101-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_40_3.0.101_108.101-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_40_3.0.101_108.101-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_40-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_40-61.49', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_40-61.49', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-doc-html / xen-kmp-default / xen-kmp-pae / xen-libs / etc');
}
