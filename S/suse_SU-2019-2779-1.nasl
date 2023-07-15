#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2779-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(130257);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1000876", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360", "CVE-2018-17985", "CVE-2018-18309", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-19931", "CVE-2018-19932", "CVE-2018-20623", "CVE-2018-20651", "CVE-2018-20671", "CVE-2018-6323", "CVE-2018-6543", "CVE-2018-6759", "CVE-2018-6872", "CVE-2018-7208", "CVE-2018-7568", "CVE-2018-7569", "CVE-2018-7570", "CVE-2018-7642", "CVE-2018-7643", "CVE-2018-8945", "CVE-2019-1010180");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : binutils (SUSE-SU-2019:2779-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for binutils fixes the following issues :

binutils was updated to current 2.32 branch [jsc#ECO-368].

Includes following security fixes :

CVE-2018-17358: Fixed invalid memory access in
_bfd_stab_section_find_nearest_line in syms.c (bsc#1109412)

CVE-2018-17359: Fixed invalid memory access exists in bfd_zalloc in
opncls.c (bsc#1109413)

CVE-2018-17360: Fixed heap-based buffer over-read in bfd_getl32 in
libbfd.c (bsc#1109414)

CVE-2018-17985: Fixed a stack consumption problem caused by the
cplus_demangle_type (bsc#1116827)

CVE-2018-18309: Fixed an invalid memory address dereference was
discovered in read_reloc in reloc.c (bsc#1111996)

CVE-2018-18483: Fixed get_count function provided by libiberty that
allowed attackers to cause a denial of service or other unspecified
impact (bsc#1112535)

CVE-2018-18484: Fixed stack exhaustion in the C++ demangling functions
provided by libiberty, caused by recursive stack frames (bsc#1112534)

CVE-2018-18605: Fixed a heap-based buffer over-read issue was
discovered in the function sec_merge_hash_lookup causing a denial of
service (bsc#1113255)

CVE-2018-18606: Fixed a NULL pointer dereference in
_bfd_add_merge_section when attempting to merge sections with large
alignments, causing denial of service (bsc#1113252)

CVE-2018-18607: Fixed a NULL pointer dereference in elf_link_input_bfd
when used for finding STT_TLS symbols without any TLS section, causing
denial of service (bsc#1113247)

CVE-2018-19931: Fixed a heap-based buffer overflow in
bfd_elf32_swap_phdr_in in elfcode.h (bsc#1118831)

CVE-2018-19932: Fixed an integer overflow and infinite loop caused by
the IS_CONTAINED_BY_LMA (bsc#1118830)

CVE-2018-20623: Fixed a use-after-free in the error function in
elfcomm.c (bsc#1121035)

CVE-2018-20651: Fixed a denial of service via a NULL pointer
dereference in elf_link_add_object_symbols in elflink.c (bsc#1121034)

CVE-2018-20671: Fixed an integer overflow that can trigger a
heap-based buffer overflow in load_specific_debug_section in objdump.c
(bsc#1121056)

CVE-2018-1000876: Fixed integer overflow in
bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dynamic_reloc in
objdump (bsc#1120640)

CVE-2019-1010180: Fixed an out of bound memory access that could lead
to crashes (bsc#1142772)

enable xtensa architecture (Tensilica lc6 and related)

Use -ffat-lto-objects in order to provide assembly for static libs
(bsc#1141913).

Fixed some LTO build issues (bsc#1133131 bsc#1133232).

riscv: Don't check ABI flags if no code section

Fixed a segfault in ld when building some versions of pacemaker
(bsc#1154025, bsc#1154016).

Add avr, epiphany and rx to target_list so that the common binutils
can handle all objects we can create with crosses (bsc#1152590).

Update to binutils 2.32: The binutils now support for the C-SKY
processor series.

The x86 assembler now supports a -mvexwig=[0|1] option to control
encoding of VEX.W-ignored (WIG) VEX instructions. It also has a new

-mx86-used-note=[yes|no] option to generate (or not) x86 GNU property
notes.

The MIPS assembler now supports the Loongson EXTensions R2 (EXT2), the
Loongson EXTensions (EXT) instructions, the Loongson Content Address
Memory (CAM) ASE and the Loongson MultiMedia extensions Instructions
(MMI) ASE.

The addr2line, c++filt, nm and objdump tools now have a default limit
on the maximum amount of recursion that is allowed whilst demangling
strings. This limit can be disabled if necessary.

Objdump's --disassemble option can now take a parameter, specifying
the starting symbol for disassembly. Disassembly will continue from
this symbol up to the next symbol or the end of the function.

The BFD linker will now report property change in linker map file when
merging GNU properties.

The BFD linker's -t option now doesn't report members within archives,
unless -t is given twice. This makes it more useful when generating a
list of files that should be packaged for a linker bug report.

The GOLD linker has improved warning messages for relocations that
refer to discarded sections.

Improve relro support on s390 [fate#326356]

Fix broken debug symbols (bsc#1118644)

Handle ELF compressed header alignment correctly.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1109414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1113255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1118831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1141913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1154025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-1000876/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17358/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17359/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17360/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-17985/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18483/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18484/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18605/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18606/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18607/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19931/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19932/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20623/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20651/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-20671/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6323/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6543/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6759/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6872/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7208/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7568/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7569/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7570/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7642/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-7643/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-8945/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-1010180/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192779-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f92e1f7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1:zypper
in -t patch SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2019-2779=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2779=1

SUSE Linux Enterprise Module for Development Tools 15-SP1:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-SP1-2019-2779=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2779=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1010180");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-gold-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-aarch64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-arm-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-avr-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-avr-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-avr-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-epiphany-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-epiphany-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-epiphany-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-hppa64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-i386-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ia64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ia64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ia64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-m68k-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-mips-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-ppc64le-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-riscv64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-riscv64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-riscv64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-rx-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-rx-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-rx-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-s390x-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-sparc64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-spu-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-spu-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-spu-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cross-x86_64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"binutils-devel-32bit-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"cross-s390x-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"s390x", reference:"cross-x86_64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-devel-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-gold-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-gold-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-aarch64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-arm-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-avr-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-avr-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-avr-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-epiphany-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-epiphany-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-epiphany-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-hppa64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-i386-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ia64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ia64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ia64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-m68k-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-mips-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-ppc64le-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-riscv64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-riscv64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-riscv64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-rx-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-rx-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-rx-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-s390-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-s390-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-s390-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-sparc64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-spu-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-spu-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cross-spu-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"binutils-devel-32bit-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"cross-s390x-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"s390x", reference:"cross-x86_64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-devel-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-gold-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-gold-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-aarch64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-arm-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-avr-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-avr-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-avr-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-epiphany-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-epiphany-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-epiphany-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-hppa64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-i386-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ia64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ia64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ia64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-m68k-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-mips-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-ppc64le-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-riscv64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-riscv64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-riscv64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-rx-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-rx-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-rx-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-s390-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-s390-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-s390-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-sparc64-binutils-debugsource-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-spu-binutils-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-spu-binutils-debuginfo-2.32-7.5.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cross-spu-binutils-debugsource-2.32-7.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils");
}
