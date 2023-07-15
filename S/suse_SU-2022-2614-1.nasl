##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:2614-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(163686);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2017-7607",
    "CVE-2017-7608",
    "CVE-2017-7609",
    "CVE-2017-7610",
    "CVE-2017-7611",
    "CVE-2017-7612",
    "CVE-2017-7613",
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-16403",
    "CVE-2018-18310",
    "CVE-2018-18520",
    "CVE-2018-18521",
    "CVE-2019-7146",
    "CVE-2019-7148",
    "CVE-2019-7149",
    "CVE-2019-7150",
    "CVE-2019-7664",
    "CVE-2019-7665"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:2614-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : dwarves and elfutils (SUSE-SU-2022:2614-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:2614-1 advisory.

  - The handle_gnu_hash function in readelf.c in elfutils 0.168 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application crash) via a crafted ELF file. (CVE-2017-7607)

  - The ebl_object_note_type_name function in eblobjnotetypename.c in elfutils 0.168 allows remote attackers
    to cause a denial of service (heap-based buffer over-read and application crash) via a crafted ELF file.
    (CVE-2017-7608)

  - elf_compress.c in elfutils 0.168 does not validate the zlib compression factor, which allows remote
    attackers to cause a denial of service (memory consumption) via a crafted ELF file. (CVE-2017-7609)

  - The check_group function in elflint.c in elfutils 0.168 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application crash) via a crafted ELF file. (CVE-2017-7610)

  - The check_symtab_shndx function in elflint.c in elfutils 0.168 allows remote attackers to cause a denial
    of service (heap-based buffer over-read and application crash) via a crafted ELF file. (CVE-2017-7611)

  - The check_sysv_hash function in elflint.c in elfutils 0.168 allows remote attackers to cause a denial of
    service (heap-based buffer over-read and application crash) via a crafted ELF file. (CVE-2017-7612)

  - elflint.c in elfutils 0.168 does not validate the number of sections and the number of segments, which
    allows remote attackers to cause a denial of service (memory consumption) via a crafted ELF file.
    (CVE-2017-7613)

  - dwarf_getaranges in dwarf_getaranges.c in libdw in elfutils before 2018-08-18 allows remote attackers to
    cause a denial of service (heap-based buffer over-read) via a crafted file. (CVE-2018-16062)

  - libelf/elf_end.c in elfutils 0.173 allows remote attackers to cause a denial of service (double free and
    application crash) or possibly have unspecified other impact because it tries to decompress twice.
    (CVE-2018-16402)

  - libdw in elfutils 0.173 checks the end of the attributes list incorrectly in dwarf_getabbrev in
    dwarf_getabbrev.c and dwarf_hasattr in dwarf_hasattr.c, leading to a heap-based buffer over-read and an
    application crash. (CVE-2018-16403)

  - An invalid memory address dereference was discovered in dwfl_segment_report_module.c in libdwfl in
    elfutils through v0.174. The vulnerability allows attackers to cause a denial of service (application
    crash) with a crafted ELF file, as demonstrated by consider_notes. (CVE-2018-18310)

  - An Invalid Memory Address Dereference exists in the function elf_end in libelf in elfutils through v0.174.
    Although eu-size is intended to support ar files inside ar files, handle_ar in size.c closes the outer ar
    file before handling all inner entries. The vulnerability allows attackers to cause a denial of service
    (application crash) with a crafted ELF file. (CVE-2018-18520)

  - Divide-by-zero vulnerabilities in the function arlib_add_symbols() in arlib.c in elfutils 0.174 allow
    remote attackers to cause a denial of service (application crash) with a crafted ELF file, as demonstrated
    by eu-ranlib, because a zero sh_entsize is mishandled. (CVE-2018-18521)

  - In elfutils 0.175, there is a buffer over-read in the ebl_object_note function in eblobjnote.c in libebl.
    Remote attackers could leverage this vulnerability to cause a denial-of-service via a crafted elf file, as
    demonstrated by eu-readelf. (CVE-2019-7146)

  - An attempted excessive memory allocation was discovered in the function read_long_names in elf_begin.c in
    libelf in elfutils 0.174. Remote attackers could leverage this vulnerability to cause a denial-of-service
    via crafted elf input, which leads to an out-of-memory exception. NOTE: The maintainers believe this is
    not a real issue, but instead a warning caused by ASAN because the allocation is big. By setting
    ASAN_OPTIONS=allocator_may_return_null=1 and running the reproducer, nothing happens. (CVE-2019-7148)

  - A heap-based buffer over-read was discovered in the function read_srclines in dwarf_getsrclines.c in libdw
    in elfutils 0.175. A crafted input can cause segmentation faults, leading to denial-of-service, as
    demonstrated by eu-nm. (CVE-2019-7149)

  - An issue was discovered in elfutils 0.175. A segmentation fault can occur in the function elf64_xlatetom
    in libelf/elf32_xlatetom.c, due to dwfl_segment_report_module not checking whether the dyn data read from
    a core file is truncated. A crafted input can cause a program crash, leading to denial-of-service, as
    demonstrated by eu-stack. (CVE-2019-7150)

  - In elfutils 0.175, a negative-sized memcpy is attempted in elf_cvt_note in libelf/note_xlate.h because of
    an incorrect overflow check. Crafted elf input causes a segmentation fault, leading to denial of service
    (program crash). (CVE-2019-7664)

  - In elfutils 0.175, a heap-based buffer over-read was discovered in the function elf32_xlatetom in
    elf32_xlatetom.c in libelf. A crafted ELF input can cause a segmentation fault leading to denial of
    service (program crash) because ebl_core_note does not reject malformed core file notes. (CVE-2019-7665)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033085");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033088");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1033090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1082318");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1104264");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1106390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1107066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1107067");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1111973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112723");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1112726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1123685");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1125007");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-August/011724.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45bdf3f8");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7607");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7611");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7612");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16402");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16403");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-18310");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-18520");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-18521");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7146");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7148");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7150");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7664");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-7665");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16402");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dwarves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:elfutils-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdw1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdw1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdwarves-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdwarves-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdwarves1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdwarves1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libebl-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libebl-plugins-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libelf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libelf1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libelf1-32bit");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'dwarves-1.22-150300.7.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'dwarves-1.22-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'elfutils-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'elfutils-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'elfutils-lang-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'elfutils-lang-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libasm-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libasm-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libasm1-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libasm1-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdw-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdw-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdw1-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdw1-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdw1-32bit-0.177-150300.11.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdw1-32bit-0.177-150300.11.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves-devel-1.22-150300.7.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves-devel-1.22-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves-devel-32bit-1.22-150300.7.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves-devel-32bit-1.22-150300.7.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves1-1.22-150300.7.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves1-1.22-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves1-32bit-1.22-150300.7.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libdwarves1-32bit-1.22-150300.7.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libebl-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libebl-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libebl-plugins-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libebl-plugins-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libebl-plugins-32bit-0.177-150300.11.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libebl-plugins-32bit-0.177-150300.11.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libelf-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libelf-devel-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libelf1-0.177-150300.11.3.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libelf1-0.177-150300.11.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libelf1-32bit-0.177-150300.11.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libelf1-32bit-0.177-150300.11.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'dwarves-1.22-150300.7.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'elfutils-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'elfutils-lang-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libasm-devel-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libasm1-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libasm1-32bit-0.177-150300.11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdw-devel-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdw1-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdw1-32bit-0.177-150300.11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdwarves-devel-1.22-150300.7.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdwarves-devel-32bit-1.22-150300.7.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdwarves1-1.22-150300.7.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libdwarves1-32bit-1.22-150300.7.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libebl-devel-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libebl-plugins-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libebl-plugins-32bit-0.177-150300.11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libelf-devel-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libelf-devel-32bit-0.177-150300.11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libelf1-0.177-150300.11.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libelf1-32bit-0.177-150300.11.3.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']}
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
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dwarves / elfutils / elfutils-lang / libasm-devel / libasm1 / etc');
}
