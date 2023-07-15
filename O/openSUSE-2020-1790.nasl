#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1790.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142163);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/12");

  script_cve_id("CVE-2019-12972", "CVE-2019-14250", "CVE-2019-14444", "CVE-2019-17450", "CVE-2019-17451", "CVE-2019-9074", "CVE-2019-9075", "CVE-2019-9077");

  script_name(english:"openSUSE Security Update : binutils (openSUSE-2020-1790)");
  script_summary(english:"Check for the openSUSE-2020-1790 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for binutils fixes the following issues :

binutils was updated to version 2.35. (jsc#ECO-2373)

Update to binutils 2.35 :

  - The assembler can now produce DWARF-5 format line number
    tables.

  - Readelf now has a 'lint' mode to enable extra checks of
    the files it is processing.

  - Readelf will now display '[...]' when it has to truncate
    a symbol name. The old behaviour - of displaying as many
    characters as possible, up to the 80 column limit - can
    be restored by the use of the --silent-truncation
    option.

  - The linker can now produce a dependency file listing the
    inputs that it has processed, much like the -M -MP
    option supported by the compiler.

  - fix DT_NEEDED order with -flto [bsc#1163744]

Update to binutils 2.34 :

  - The disassembler (objdump --disassemble) now has an
    option to generate ascii art thats show the arcs between
    that start and end points of control flow instructions.

  - The binutils tools now have support for debuginfod.
    Debuginfod is a HTTP service for distributing ELF/DWARF
    debugging information as well as source code. The tools
    can now connect to debuginfod servers in order to
    download debug information about the files that they are
    processing.

  - The assembler and linker now support the generation of
    ELF format files for the Z80 architecture.

  - Add new subpackages for libctf and libctf-nobfd.

  - Disable LTO due to bsc#1163333.

  - Includes fixes for these CVEs: bsc#1153768 aka
    CVE-2019-17451 aka PR25070 bsc#1153770 aka
    CVE-2019-17450 aka PR25078

  - fix various build fails on aarch64 (PR25210,
    bsc#1157755).

Update to binutils 2.33.1 :

  - Adds support for the Arm Scalable Vector Extension
    version 2 (SVE2) instructions, the Arm Transactional
    Memory Extension (TME) instructions and the Armv8.1-M
    Mainline and M-profile Vector Extension (MVE)
    instructions.

  - Adds support for the Arm Cortex-A76AE, Cortex-A77 and
    Cortex-M35P processors and the AArch64 Cortex-A34,
    Cortex-A65, Cortex-A65AE, Cortex-A76AE, and Cortex-A77
    processors.

  - Adds a .float16 directive for both Arm and AArch64 to
    allow encoding of 16-bit floating point literals.

  - For MIPS, Add -m[no-]fix-loongson3-llsc option to fix
    (or not) Loongson3 LLSC Errata. Add a
    --enable-mips-fix-loongson3-llsc=[yes|no] configure time
    option to set the default behavior. Set the default if
    the configure option is not used to 'no'.

  - The Cortex-A53 Erratum 843419 workaround now supports a
    choice of which workaround to use. The option
    --fix-cortex-a53-843419 now takes an optional argument
    --fix-cortex-a53-843419[=full|adr|adrp] which can be
    used to force a particular workaround to be used. See
    --help for AArch64 for more details.

  - Add support for GNU_PROPERTY_AARCH64_FEATURE_1_BTI and
    GNU_PROPERTY_AARCH64_FEATURE_1_PAC in ELF GNU program
    properties in the AArch64 ELF linker. 

  - Add -z force-bti for AArch64 to enable
    GNU_PROPERTY_AARCH64_FEATURE_1_BTI on output while
    warning about missing GNU_PROPERTY_AARCH64_FEATURE_1_BTI
    on inputs and use PLTs protected with BTI.

  - Add -z pac-plt for AArch64 to pick PAC enabled PLTs.

  - Add --source-comment[=<txt>] option to objdump which if
    present, provides a prefix to source code lines
    displayed in a disassembly.

  - Add --set-section-alignment
    <section-name>=<power-of-2-align> option to objcopy to
    allow the changing of section alignments.

  - Add --verilog-data-width option to objcopy for verilog
    targets to control width of data elements in verilog hex
    format.

  - The separate debug info file options of readelf
    (--debug-dump=links and --debug-dump=follow) and objdump
    (--dwarf=links and

    --dwarf=follow-links) will now display and/or follow
    multiple links if more than one are present in a file.
    (This usually happens when gcc's -gsplit-dwarf option is
    used). In addition objdump's --dwarf=follow-links now
    also affects its other display options, so that for
    example, when combined with

    --syms it will cause the symbol tables in any linked
    debug info files to also be displayed. In addition when
    combined with

    --disassemble the --dwarf= follow-links option will
    ensure that any symbol tables in the linked files are
    read and used when disassembling code in the main file.

  - Add support for dumping types encoded in the Compact
    Type Format to objdump and readelf.

  - Includes fixes for these CVEs: bsc#1126826 aka
    CVE-2019-9077 aka PR1126826 bsc#1126829 aka
    CVE-2019-9075 aka PR1126829 bsc#1126831 aka
    CVE-2019-9074 aka PR24235 bsc#1140126 aka CVE-2019-12972
    aka PR23405 bsc#1143609 aka CVE-2019-14444 aka PR24829
    bsc#1142649 aka CVE-2019-14250 aka PR90924

  - Add xBPF target

  - Fix various problems with DWARF 5 support in gas

  - fix nm -B for objects compiled with -flto and -fcommon.

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1126831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1140126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1143609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1153770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1160590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1163744"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected binutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9077");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:binutils-gold-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-aarch64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-arm-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-avr-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-epiphany-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-epiphany-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-epiphany-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-hppa64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-i386-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ia64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-m68k-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-mips-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-ppc64le-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-riscv64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-riscv64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-riscv64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-rx-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-rx-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-rx-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-s390x-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-sparc64-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cross-spu-binutils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libctf-nobfd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libctf-nobfd0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libctf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libctf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"binutils-devel-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"binutils-gold-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"binutils-gold-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libctf-nobfd0-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libctf-nobfd0-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libctf0-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libctf0-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"binutils-devel-32bit-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-aarch64-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-aarch64-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-aarch64-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-arm-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-arm-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-arm-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-avr-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-avr-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-avr-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-epiphany-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-epiphany-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-epiphany-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-hppa-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-hppa-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-hppa-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-hppa64-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-hppa64-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-hppa64-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-i386-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-i386-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-i386-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ia64-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ia64-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ia64-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-m68k-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-m68k-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-m68k-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-mips-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-mips-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-mips-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc64-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc64-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc64-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc64le-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc64le-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-ppc64le-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-riscv64-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-riscv64-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-riscv64-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-rx-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-rx-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-rx-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-s390-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-s390-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-s390-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-s390x-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-s390x-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-s390x-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-sparc-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-sparc-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-sparc-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-sparc64-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-sparc64-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-sparc64-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-spu-binutils-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-spu-binutils-debuginfo-2.35-lp151.3.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"cross-spu-binutils-debugsource-2.35-lp151.3.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "binutils / binutils-debuginfo / binutils-debugsource / etc");
}
