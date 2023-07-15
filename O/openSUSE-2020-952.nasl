#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-952.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138733);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2018-1000667", "CVE-2018-10016", "CVE-2018-10254", "CVE-2018-10316", "CVE-2018-16382", "CVE-2018-16517", "CVE-2018-16999", "CVE-2018-19214", "CVE-2018-19215", "CVE-2018-19216", "CVE-2018-8881", "CVE-2018-8882", "CVE-2018-8883");

  script_name(english:"openSUSE Security Update : nasm (openSUSE-2020-952)");
  script_summary(english:"Check for the openSUSE-2020-952 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nasm fixes the following issues :

nasm was updated to version 2.14.02.

This allows building of Mozilla Firefox 78ESR and also contains lots
of bugfixes, security fixes and improvements.

  - Fix crash due to multiple errors or warnings during the
    code generation pass if a list file is specified.

  - Create all system-defined macros defore processing
    command-line given preprocessing directives (-p, -d, -u,
    --pragma, --before).

  - If debugging is enabled, define a __DEBUG_FORMAT__
    predefined macro. See section 4.11.7.

  - Fix an assert for the case in the obj format when a SEG
    operator refers to an EXTERN symbol declared further
    down in the code.

  - Fix a corner case in the floating-point code where a
    binary, octal or hexadecimal floating-point having at
    least 32, 11, or 8 mantissa digits could produce
    slightly incorrect results under very specific
    conditions.

  - Support -MD without a filename, for gcc compatibility.
    -MF can be used to set the dependencies output filename.
    See section 2.1.7.

  - Fix -E in combination with -MD. See section 2.1.21.

  - Fix missing errors on redefined labels; would cause
    convergence failure instead which is very slow and not
    easy to debug.

  - Duplicate definitions of the same label with the same
    value is now explicitly permitted (2.14 would allow it
    in some circumstances.)

  - Add the option --no-line to ignore %line directives in
    the source. See section 2.1.33 and section 4.10.1.

  - Changed -I option semantics by adding a trailing path
    separator unconditionally.

  - Fixed null dereference in corrupted invalid single line
    macros.

  - Fixed division by zero which may happen if source code
    is malformed.

  - Fixed out of bound access in processing of malformed
    segment override.

  - Fixed out of bound access in certain EQU parsing.

  - Fixed buffer underflow in float parsing.

  - Added SGX (Intel Software Guard Extensions)
    instructions.

  - Added +n syntax for multiple contiguous registers.

  - Fixed subsections_via_symbols for macho object format.

  - Added the --gprefix, --gpostfix, --lprefix, and
    --lpostfix command line options, to allow command line
    base symbol renaming. See section 2.1.28.

  - Allow label renaming to be specified by %pragma in
    addition to from the command line. See section 6.9.

  - Supported generic %pragma namespaces, output and debug.
    See section 6.10.

  - Added the --pragma command line option to inject a
    %pragma directive. See section 2.1.29.

  - Added the --before command line option to accept
    preprocess statement before input. See section 2.1.30.

  - Added AVX512 VBMI2 (Additional Bit Manipulation), VNNI
    (Vector Neural Network), BITALG (Bit Algorithm), and
    GFNI (Galois Field New Instruction) instructions.

  - Added the STATIC directive for local symbols that should
    be renamed using global-symbol rules. See section 6.8.

  - Allow a symbol to be defined as EXTERN and then later
    overridden as GLOBAL or COMMON. Furthermore, a symbol
    declared EXTERN and then defined will be treated as
    GLOBAL. See section 6.5.

  - The GLOBAL directive no longer is required to precede
    the definition of the symbol.

  - Support private_extern as macho specific extension to
    the GLOBAL directive. See section 7.8.5.

  - Updated UD0 encoding to match with the specification

  - Added the --limit-X command line option to set execution
    limits. See section 2.1.31.

  - Updated the Codeview version number to be aligned with
    MASM.

  - Added the --keep-all command line option to preserve
    output files. See section 2.1.32.

  - Added the --include command line option, an alias to -P
    (section 2.1.18).

  - Added the --help command line option as an alias to -h
    (section 3.1).

  - Added -W, -D, and -Q suffix aliases for RET instructions
    so the operand sizes of these instructions can be
    encoded without using o16, o32 or o64.

New upstream version 2.13.03 :

  - Add flags: AES, VAES, VPCLMULQDQ

  - Add VPCLMULQDQ instruction

  - elf: Add missing dwarf loc section

  - documentation updates This update was imported from the
    SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1090840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173538"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nasm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8881");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nasm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nasm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nasm-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"nasm-2.14.02-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nasm-debuginfo-2.14.02-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nasm-debugsource-2.14.02-lp151.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nasm / nasm-debuginfo / nasm-debugsource");
}
