#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:3060-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(143614);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-12972", "CVE-2019-14250", "CVE-2019-14444", "CVE-2019-17450", "CVE-2019-17451", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : binutils (SUSE-SU-2020:3060-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for binutils fixes the following issues :

binutils was updated to version 2.35. (jsc#ECO-2373)

Update to binutils 2.35 :

The assembler can now produce DWARF-5 format line number tables.

Readelf now has a 'lint' mode to enable extra checks of the files it
is processing.

Readelf will now display '[...]' when it has to truncate a symbol
name. The old behaviour - of displaying as many characters as
possible, up to the 80 column limit - can be restored by the use of
the

--silent-truncation option.

The linker can now produce a dependency file listing the inputs that
it has processed, much like the -M -MP option supported by the
compiler.

fix DT_NEEDED order with -flto [bsc#1163744]

Update to binutils 2.34 :

The disassembler (objdump --disassemble) now has an option to generate
ascii art thats show the arcs between that start and end points of
control flow instructions.

The binutils tools now have support for debuginfod. Debuginfod is a
HTTP service for distributing ELF/DWARF debugging information as well
as source code. The tools can now connect to debuginfod servers in
order to download debug information about the files that they are
processing.

The assembler and linker now support the generation of ELF format
files for the Z80 architecture.

Add new subpackages for libctf and libctf-nobfd.

Disable LTO due to bsc#1163333.

Includes fixes for these CVEs: bsc#1153768 aka CVE-2019-17451 aka
PR25070 bsc#1153770 aka CVE-2019-17450 aka PR25078

fix various build fails on aarch64 (PR25210, bsc#1157755).

Update to binutils 2.33.1 :

Adds support for the Arm Scalable Vector Extension version 2 (SVE2)
instructions, the Arm Transactional Memory Extension (TME)
instructions and the Armv8.1-M Mainline and M-profile Vector Extension
(MVE) instructions.

Adds support for the Arm Cortex-A76AE, Cortex-A77 and Cortex-M35P
processors and the AArch64 Cortex-A34, Cortex-A65, Cortex-A65AE,
Cortex-A76AE, and Cortex-A77 processors.

Adds a .float16 directive for both Arm and AArch64 to allow encoding
of 16-bit floating point literals.

For MIPS, Add -m[no-]fix-loongson3-llsc option to fix (or not)
Loongson3 LLSC Errata. Add a --enable-mips-fix-loongson3-llsc=[yes|no]
configure time option to set the default behavior. Set the default if
the configure option is not used to 'no'.

The Cortex-A53 Erratum 843419 workaround now supports a choice of
which workaround to use. The option --fix-cortex-a53-843419 now takes
an optional argument --fix-cortex-a53-843419[=full|adr|adrp] which can
be used to force a particular workaround to be used. See --help for
AArch64 for more details.

Add support for GNU_PROPERTY_AARCH64_FEATURE_1_BTI and
GNU_PROPERTY_AARCH64_FEATURE_1_PAC in ELF GNU program properties in
the AArch64 ELF linker.

Add -z force-bti for AArch64 to enable
GNU_PROPERTY_AARCH64_FEATURE_1_BTI on output while warning about
missing GNU_PROPERTY_AARCH64_FEATURE_1_BTI on inputs and use PLTs
protected with BTI.

Add -z pac-plt for AArch64 to pick PAC enabled PLTs.

Add --source-comment[=<txt>] option to objdump which if present,
provides a prefix to source code lines displayed in a disassembly.

Add --set-section-alignment <section-name>=<power-of-2-align> option
to objcopy to allow the changing of section alignments.

Add --verilog-data-width option to objcopy for verilog targets to
control width of data elements in verilog hex format.

The separate debug info file options of readelf (--debug-dump=links
and

--debug-dump=follow) and objdump (--dwarf=links and

--dwarf=follow-links) will now display and/or follow
multiple links if more than one are present in a file. (This
usually happens when gcc's

-gsplit-dwarf option is used). In addition objdump's

--dwarf=follow-links now also affects its other display
options, so that for example, when combined with

--syms it will cause the symbol tables in any linked debug
info files to also be displayed. In addition when combined
with

--disassemble the --dwarf= follow-links option will ensure
that any symbol tables in the linked files are read and used
when disassembling code in the main file.

Add support for dumping types encoded in the Compact Type Format to
objdump and readelf.

Includes fixes for these CVEs: bsc#1126826 aka CVE-2019-9077 aka
PR1126826 bsc#1126829 aka CVE-2019-9075 aka PR1126829 bsc#1126831 aka
CVE-2019-9074 aka PR24235 bsc#1140126 aka CVE-2019-12972 aka PR23405
bsc#1143609 aka CVE-2019-14444 aka PR24829 bsc#1142649 aka
CVE-2019-14250 aka PR90924

Add xBPF target

Fix various problems with DWARF 5 support in gas

fix nm -B for objects compiled with -flto and -fcommon.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1140126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1142649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1143609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1157755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1160590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1163744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12972/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14250/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-14444/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17450/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-17451/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9074/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9075/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-9077/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20203060-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02eaac83"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP2-2020-3060=1

SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Packagehub-Subpackages-15-SP1-2020-3060=1

SUSE Linux Enterprise Module for Development Tools 15-SP2 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP2-2020-3060=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-3060=1

SUSE Linux Enterprise Module for Basesystem 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP2-2020-3060=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-3060=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:binutils-gold-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf-nobfd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libctf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"binutils-devel-32bit-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-debugsource-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-devel-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-gold-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"binutils-gold-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libctf-nobfd0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libctf-nobfd0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libctf0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libctf0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", cpu:"x86_64", reference:"binutils-devel-32bit-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"binutils-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"binutils-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"binutils-debugsource-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"binutils-devel-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"binutils-gold-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"binutils-gold-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libctf-nobfd0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libctf-nobfd0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libctf0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"libctf0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"binutils-devel-32bit-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-debugsource-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-devel-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-gold-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"binutils-gold-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libctf-nobfd0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libctf-nobfd0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libctf0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libctf0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", cpu:"x86_64", reference:"binutils-devel-32bit-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"binutils-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"binutils-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"binutils-debugsource-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"binutils-devel-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"binutils-gold-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"binutils-gold-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libctf-nobfd0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libctf-nobfd0-debuginfo-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libctf0-2.35-7.11.1")) flag++;
if (rpm_check(release:"SLED15", sp:"2", reference:"libctf0-debuginfo-2.35-7.11.1")) flag++;


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
