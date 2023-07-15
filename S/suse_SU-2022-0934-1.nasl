#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:0934-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159175);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id(
    "CVE-2020-16590",
    "CVE-2020-16591",
    "CVE-2020-16592",
    "CVE-2020-16593",
    "CVE-2020-16598",
    "CVE-2020-16599",
    "CVE-2020-35448",
    "CVE-2020-35493",
    "CVE-2020-35496",
    "CVE-2020-35507",
    "CVE-2021-3487",
    "CVE-2021-20197",
    "CVE-2021-20284",
    "CVE-2021-20294"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:0934-1");

  script_name(english:"SUSE SLES15 Security Update : binutils (SUSE-SU-2022:0934-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:0934-1 advisory.

  - A double free vulnerability exists in the Binary File Descriptor (BFD) (aka libbrd) in GNU Binutils 2.35
    in the process_symbol_table, as demonstrated in readelf, via a crafted file. (CVE-2020-16590)

  - A Denial of Service vulnerability exists in the Binary File Descriptor (BFD) in GNU Binutils 2.35 due to
    an invalid read in process_symbol_table, as demonstrated in readeif. (CVE-2020-16591)

  - A use after free issue exists in the Binary File Descriptor (BFD) library (aka libbfd) in GNU Binutils
    2.34 in bfd_hash_lookup, as demonstrated in nm-new, that can cause a denial of service via a crafted file.
    (CVE-2020-16592)

  - A Null Pointer Dereference vulnerability exists in the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.35, in scan_unit_for_symbols, as demonstrated in addr2line, that can
    cause a denial of service via a crafted file. (CVE-2020-16593)

  - A Null Pointer Dereference vulnerability exists in the Binary File Descriptor (BFD) library (aka libbfd),
    as distributed in GNU Binutils 2.35, in _bfd_elf_get_symbol_version_string, as demonstrated in nm-new,
    that can cause a denial of service via a crafted file. (CVE-2020-16599)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.35.1. A heap-based buffer over-read can occur in bfd_getl_signed_32 in libbfd.c because
    sh_entsize is not validated in _bfd_elf_slurp_secondary_reloc_section in elf.c. (CVE-2020-35448)

  - A flaw exists in binutils in bfd/pef.c. An attacker who is able to submit a crafted PEF file to be parsed
    by objdump could cause a heap buffer overflow -> out-of-bounds read that could lead to an impact to
    application availability. This flaw affects binutils versions prior to 2.34. (CVE-2020-35493)

  - There's a flaw in bfd_pef_scan_start_address() of bfd/pef.c in binutils which could allow an attacker who
    is able to submit a crafted file to be processed by objdump to cause a NULL pointer dereference. The
    greatest threat of this flaw is to application availability. This flaw affects binutils versions prior to
    2.34. (CVE-2020-35496)

  - There's a flaw in bfd_pef_parse_function_stubs of bfd/pef.c in binutils in versions prior to 2.34 which
    could allow an attacker who is able to submit a crafted file to be processed by objdump to cause a NULL
    pointer dereference. The greatest threat of this flaw is to application availability. (CVE-2020-35507)

  - There is an open race window when writing output in the following utilities in GNU binutils version 2.35
    and earlier:ar, objcopy, strip, ranlib. When these utilities are run as a privileged user (presumably as
    part of a script updating binaries across different users), an unprivileged user can trick these utilities
    into getting ownership of arbitrary files through a symlink. (CVE-2021-20197)

  - A flaw was found in GNU Binutils 2.35.1, where there is a heap-based buffer overflow in
    _bfd_elf_slurp_secondary_reloc_section in elf.c due to the number of symbols not calculated correctly. The
    highest threat from this vulnerability is to system availability. (CVE-2021-20284)

  - A flaw was found in binutils readelf 2.35 program. An attacker who is able to convince a victim using
    readelf to read a crafted file could trigger a stack buffer overflow, out-of-bounds write of arbitrary
    data supplied by the attacker. The highest impact of this flaw is to confidentiality, integrity, and
    availability. (CVE-2021-20294)

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179901");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180451");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184794");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192267");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-March/010497.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42815fb8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16590");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16591");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16592");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16593");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-16599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35448");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35493");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35496");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35507");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20294");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3487");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20294");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'binutils-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-devel-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-devel-32bit-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf-nobfd0-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf0-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-devel-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-devel-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-devel-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-devel-32bit-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15', 'sles-ltss-release-15']},
    {'reference':'libctf-nobfd0-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf-nobfd0-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf-nobfd0-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf0-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf0-2.37-6.23.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'libctf0-2.37-6.23.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'binutils-2.37-6.23.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'binutils-devel-2.37-6.23.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libctf-nobfd0-2.37-6.23.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'libctf0-2.37-6.23.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-devel / binutils-devel-32bit / libctf-nobfd0 / etc');
}
