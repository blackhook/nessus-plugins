#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1418.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119023);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856", "CVE-2018-15857", "CVE-2018-15858", "CVE-2018-15859", "CVE-2018-15861", "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");

  script_name(english:"openSUSE Security Update : libxkbcommon (openSUSE-2018-1418)");
  script_summary(english:"Check for the openSUSE-2018-1418 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxkbcommon to version 0.8.2 fixes the following
issues :

  - Fix a few NULL-dereferences, out-of-bounds access and
    undefined behavior in the XKB text format parser.

  - CVE-2018-15853: Endless recursion could have been used
    by local attackers to crash xkbcommon users by supplying
    a crafted keymap file that triggers boolean negation
    (bsc#1105832).

  - CVE-2018-15854: Unchecked NULL pointer usage could have
    been used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file, because geometry tokens were desupported
    incorrectly (bsc#1105832).

  - CVE-2018-15855: Unchecked NULL pointer usage could have
    been used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file, because the XkbFile for an xkb_geometry
    section was mishandled (bsc#1105832).

  - CVE-2018-15856: An infinite loop when reaching EOL
    unexpectedly could be used by local attackers to cause a
    denial of service during parsing of crafted keymap files
    (bsc#1105832).

  - CVE-2018-15857: An invalid free in
    ExprAppendMultiKeysymList could have been used by local
    attackers to crash xkbcommon keymap parsers or possibly
    have unspecified other impact by supplying a crafted
    keymap file (bsc#1105832).

  - CVE-2018-15858: Unchecked NULL pointer usage when
    handling invalid aliases in CopyKeyAliasesToKeymap could
    have been used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file (bsc#1105832).

  - CVE-2018-15859: Unchecked NULL pointer usage when
    parsing invalid atoms in ExprResolveLhs could have been
    used by local attackers to crash (NULL pointer
    dereference) the xkbcommon parser by supplying a crafted
    keymap file, because lookup failures are mishandled
    (bsc#1105832).

  - CVE-2018-15861: Unchecked NULL pointer usage in
    ExprResolveLhs could have been used by local attackers
    to crash (NULL pointer dereference) the xkbcommon parser
    by supplying a crafted keymap file that triggers an
    xkb_intern_atom failure (bsc#1105832).

  - CVE-2018-15862: Unchecked NULL pointer usage in
    LookupModMask could have been used by local attackers to
    crash (NULL pointer dereference) the xkbcommon parser by
    supplying a crafted keymap file with invalid virtual
    modifiers (bsc#1105832).

  - CVE-2018-15863: Unchecked NULL pointer usage in
    ResolveStateAndPredicate could have been used by local
    attackers to crash (NULL pointer dereference) the
    xkbcommon parser by supplying a crafted keymap file with
    a no-op modmask expression (bsc#1105832).

  - CVE-2018-15864: Unchecked NULL pointer usage in
    resolve_keysym could have been used by local attackers
    to crash (NULL pointer dereference) the xkbcommon parser
    by supplying a crafted keymap file, because a map access
    attempt can occur for a map that was never created
    (bsc#1105832).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxkbcommon packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-x11-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-x11-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-x11-0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-x11-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon-x11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxkbcommon0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon-debugsource-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon-devel-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon-x11-0-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon-x11-0-debuginfo-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon-x11-devel-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon0-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxkbcommon0-debuginfo-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxkbcommon-devel-32bit-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxkbcommon-x11-0-32bit-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxkbcommon-x11-0-32bit-debuginfo-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxkbcommon-x11-devel-32bit-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxkbcommon0-32bit-0.8.2-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxkbcommon0-32bit-debuginfo-0.8.2-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxkbcommon-debugsource / libxkbcommon-devel / libxkbcommon-x11-0 / etc");
}
