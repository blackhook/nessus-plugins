#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14440-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150632);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-10713",
    "CVE-2020-14308",
    "CVE-2020-14309",
    "CVE-2020-14310",
    "CVE-2020-14311",
    "CVE-2020-15706",
    "CVE-2020-15707"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14440-1");
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"CEA-ID", value:"CEA-2020-0061");

  script_name(english:"SUSE SLES11 Security Update : grub2 (SUSE-SU-2020:14440-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14440-1 advisory.

  - A flaw was found in grub2, prior to version 2.06. An attacker may use the GRUB 2 flaw to hijack and tamper
    the GRUB verification process. This flaw also allows the bypass of Secure Boot protections. In order to
    load an untrusted or modified kernel, an attacker would first need to establish access to the system such
    as gaining physical access, obtain the ability to alter a pxe-boot network, or have remote access to a
    networked system with root access. With this access, an attacker could then craft a string to cause a
    buffer overflow by injecting a malicious payload that leads to arbitrary code execution within GRUB. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2020-10713)

  - In grub2 versions before 2.06 the grub memory allocator doesn't check for possible arithmetic overflows on
    the requested allocation size. This leads the function to return invalid memory allocations which can be
    further used to cause possible integrity, confidentiality and availability impacts during the boot
    process. (CVE-2020-14308)

  - There's an issue with grub2 in all versions before 2.06 when handling squashfs filesystems containing a
    symbolic link with name length of UINT32 bytes in size. The name size leads to an arithmetic overflow
    leading to a zero-size allocation further causing a heap-based buffer overflow with attacker controlled
    data. (CVE-2020-14309)

  - There is an issue on grub2 before version 2.06 at function read_section_as_string(). It expects a font
    name to be at max UINT32_MAX - 1 length in bytes but it doesn't verify it before proceed with buffer
    allocation to read the value from the font value. An attacker may leverage that by crafting a malicious
    font file which has a name with UINT32_MAX, leading to read_section_as_string() to an arithmetic overflow,
    zero-sized allocation and further heap-based buffer overflow. (CVE-2020-14310)

  - There is an issue with grub2 before version 2.06 while handling symlink on ext filesystems. A filesystem
    containing a symbolic link with an inode size of UINT32_MAX causes an arithmetic overflow leading to a
    zero-sized memory allocation with subsequent heap-based buffer overflow. (CVE-2020-14311)

  - GRUB2 contains a race condition in grub_script_function_create() leading to a use-after-free vulnerability
    which can be triggered by redefining a function whilst the same function is already executing, leading to
    arbitrary code execution and secure boot restriction bypass. This issue affects GRUB2 version 2.04 and
    prior versions. (CVE-2020-15706)

  - Integer overflows were discovered in the functions grub_cmd_initrd and grub_initrd_init in the efilinux
    component of GRUB2, as shipped in Debian, Red Hat, and Ubuntu (the functionality is not included in GRUB2
    upstream), leading to a heap-based buffer overflow. These could be triggered by an extremely large number
    of arguments to the initrd command on 32-bit architectures, or a crafted filesystem with very large files
    on any architecture. An attacker could use this to execute arbitrary code and bypass UEFI Secure Boot
    restrictions. This issue affects GRUB2 version 2.04 and prior versions. (CVE-2020-15707)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1084632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173812");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174570");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-July/007201.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4a207db");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14308");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14309");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14311");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15707");
  script_set_attribute(attribute:"solution", value:
"Update the affected grub2-x86_64-efi and / or grub2-x86_64-xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14309");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-x86_64-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:grub2-x86_64-xen");
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
    {'reference':'grub2-x86_64-efi-2.00-0.66.15', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'grub2-x86_64-xen-2.00-0.66.15', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'grub2-x86_64-efi-2.00-0.66.15', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'grub2-x86_64-xen-2.00-0.66.15', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2-x86_64-efi / grub2-x86_64-xen');
}
