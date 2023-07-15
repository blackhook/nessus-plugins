#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3616-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154898);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

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
    "CVE-2021-20284"
  );

  script_name(english:"openSUSE 15 Security Update : binutils (openSUSE-SU-2021:3616-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:3616-1 advisory.

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

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Further investigation showed that it was not a security issue. Notes: none. (CVE-2020-16598)

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

  - There's a flaw in the BFD library of binutils in versions before 2.36. An attacker who supplies a crafted
    file to an application linked with BFD, and using the DWARF functionality, could cause an impact to system
    availability by way of excessive memory consumption. (CVE-2021-3487)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184794");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4TQ3DLF5YEQDDJUON6WGBX2HVVM7FOLB/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?728c1272");
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
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3487");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35448");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-20197");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bpftrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bpftrace-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-epiphany-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-riscv64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-rx-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-x86_64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libctf0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
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
    {'reference':'binutils-2.37-7.21.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-devel-2.37-7.21.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-devel-32bit-2.37-7.21.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'binutils-gold-2.37-7.21.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftrace-0.11.4-3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'bpftrace-tools-0.11.4-3.2.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-aarch64-binutils-2.37-7.21.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-aarch64-binutils-2.37-7.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-arm-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-avr-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-epiphany-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-hppa-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-hppa64-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-i386-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-ia64-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-m68k-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-mips-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-ppc-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-ppc64-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-ppc64le-binutils-2.37-7.21.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-ppc64le-binutils-2.37-7.21.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-ppc64le-binutils-2.37-7.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-riscv64-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-rx-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-s390-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-s390x-binutils-2.37-7.21.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-s390x-binutils-2.37-7.21.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-sparc-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-sparc64-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-spu-binutils-2.37-7.21.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-x86_64-binutils-2.37-7.21.1', 'cpu':'aarch64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cross-x86_64-binutils-2.37-7.21.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libctf-nobfd0-2.37-7.21.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libctf0-2.37-7.21.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-devel / binutils-devel-32bit / binutils-gold / etc');
}
