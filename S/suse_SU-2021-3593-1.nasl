#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3593-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154861);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/03");

  script_cve_id(
    "CVE-2019-9074",
    "CVE-2019-9075",
    "CVE-2019-9077",
    "CVE-2019-12972",
    "CVE-2019-14250",
    "CVE-2019-14444",
    "CVE-2019-17450",
    "CVE-2019-17451",
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
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3593-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : binutils (SUSE-SU-2021:3593-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:3593-1 advisory.

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. There is a heap-based buffer over-read in _bfd_doprnt in bfd.c because elf_object_p in
    elfcode.h mishandles an e_shstrndx section of type SHT_GROUP by omitting a trailing '\0' character.
    (CVE-2019-12972)

  - An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.32. simple_object_elf_match in
    simple-object-elf.c does not check for a zero shstrndx value, leading to an integer overflow and resultant
    heap-based buffer overflow. (CVE-2019-14250)

  - apply_relocations in readelf.c in GNU Binutils 2.32 contains an integer overflow that allows attackers to
    trigger a write access violation (in byte_put_little_endian function in elfcomm.c) via an ELF file, as
    demonstrated by readelf. (CVE-2019-14444)

  - find_abstract_instance in dwarf2.c in the Binary File Descriptor (BFD) library (aka libbfd), as
    distributed in GNU Binutils 2.32, allows remote attackers to cause a denial of service (infinite recursion
    and application crash) via a crafted ELF file. (CVE-2019-17450)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an integer overflow leading to a SEGV in _bfd_dwarf2_find_nearest_line in dwarf2.c,
    as demonstrated by nm. (CVE-2019-17451)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is an out-of-bounds read leading to a SEGV in bfd_getl32 in libbfd.c, when called from
    pex64_get_runtime_function in pei-x86_64.c. (CVE-2019-9074)

  - An issue was discovered in the Binary File Descriptor (BFD) library (aka libbfd), as distributed in GNU
    Binutils 2.32. It is a heap-based buffer overflow in _bfd_archive_64_bit_slurp_armap in archive64.c.
    (CVE-2019-9075)

  - An issue was discovered in GNU Binutils 2.32. It is a heap-based buffer overflow in process_mips_specific
    in readelf.c via a malformed MIPS option section. (CVE-2019-9077)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126826");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126829");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1126831");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1140126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1142649");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1143609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153768");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1153770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157755");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160254");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1160590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163333");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163744");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179341");
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
  # https://lists.suse.com/pipermail/sle-security-updates/2021-November/009687.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c459db79");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-12972");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14444");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17450");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-17451");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9074");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-9077");
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
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9077");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-spu-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
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
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + sp);
if (os_ver == "SLES12" && (! preg(pattern:"^(2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2/3/4/5", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'binutils-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.3'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.4'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-12.5'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'binutils-gold-2.37-9.39.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'binutils-gold-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'cross-ppc-binutils-2.37-9.39.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'cross-ppc-binutils-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'cross-spu-binutils-2.37-9.39.1', 'sp':'5', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'cross-spu-binutils-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-sdk-release-12.5'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.2'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'3', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.3'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'4', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.4'},
    {'reference':'binutils-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'binutils-devel-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libctf-nobfd0-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'},
    {'reference':'libctf0-2.37-9.39.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-12.5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'binutils / binutils-devel / binutils-gold / cross-ppc-binutils / etc');
}
