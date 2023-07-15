#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2650-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(129879);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-1000876", "CVE-2018-17358", "CVE-2018-17359", "CVE-2018-17360", "CVE-2018-17985", "CVE-2018-18309", "CVE-2018-18483", "CVE-2018-18484", "CVE-2018-18605", "CVE-2018-18606", "CVE-2018-18607", "CVE-2018-19931", "CVE-2018-19932", "CVE-2018-20623", "CVE-2018-20651", "CVE-2018-20671", "CVE-2019-1010180");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : binutils (SUSE-SU-2019:2650-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for binutils fixes the following issues :

binutils was updated to current 2.32 branch @7b468db3 [jsc#ECO-368] :

Includes the following security fixes :

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

Enable xtensa architecture (Tensilica lc6 and related)

Use -ffat-lto-objects in order to provide assembly for static libs
(bsc#1141913).

Fixed some LTO problems (bsc#1133131 bsc#1133232).

riscv: Don't check ABI flags if no code section

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
    value:"https://www.suse.com/security/cve/CVE-2019-1010180/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192650-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc1443fc"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2019-2650=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2019-2650=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2019-2650=1

SUSE Linux Enterprise Software Development Kit 12-SP5:zypper in -t
patch SUSE-SLE-SDK-12-SP5-2019-2650=1

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-2650=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2019-2650=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2019-2650=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2019-2650=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2019-2650=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-2650=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2019-2650=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2019-2650=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2019-2650=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2019-2650=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2019-2650=1

SUSE Linux Enterprise Desktop 12-SP5:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP5-2019-2650=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-2650=1

SUSE Enterprise Storage 5:zypper in -t patch
SUSE-Storage-5-2019-2650=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2019-2650=1

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2019-2650=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1010180");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1|2|3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2/3/4/5", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"binutils-debugsource-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"binutils-devel-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"binutils-debugsource-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"binutils-debugsource-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-debugsource-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"binutils-devel-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"binutils-debugsource-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"binutils-debugsource-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"binutils-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"binutils-debuginfo-2.32-9.33.1")) flag++;
if (rpm_check(release:"SLED12", sp:"5", cpu:"x86_64", reference:"binutils-debugsource-2.32-9.33.1")) flag++;


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
