#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2494.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(130940);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2019-1010180");

  script_name(english:"openSUSE Security Update : gdb (openSUSE-2019-2494)");
  script_summary(english:"Check for the openSUSE-2019-2494 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for gdb fixes the following issues :

Update to gdb 8.3.1: (jsc#ECO-368)

Security issues fixed :

  - CVE-2019-1010180: Fixed a potential buffer overflow when
    loading ELF sections larger than the file. (bsc#1142772)

Upgrade libipt from v2.0 to v2.0.1.

  - Enable librpm for version > librpm.so.3 [bsc#1145692] :

  - Allow any librpm.so.x

  - Add %build test to check for 'zypper install
    <rpm-packagename>' message

  - Copy gdbinit from fedora master @ 25caf28. Add
    gdbinit.without-python, and use it for --without=python.

Rebase to 8.3 release (as in fedora 30 @ 1e222a3).

  - DWARF index cache: GDB can now automatically save
    indices of DWARF symbols on disk to speed up further
    loading of the same binaries.

  - Ada task switching is now supported on aarch64-elf
    targets when debugging a program using the Ravenscar
    Profile.

  - Terminal styling is now available for the CLI and the
    TUI.

  - Removed support for old demangling styles arm, edg, gnu,
    hp and lucid.

  - Support for new native configuration RISC-V GNU/Linux
    (riscv*-*-linux*).

  - Implemented access to more POWER8 registers.
    [fate#326120, fate#325178]

  - Handle most of new s390 arch13 instructions.
    [fate#327369, jsc#ECO-368]

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/327369"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdb-testresults");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdbserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gdbserver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"gdb-8.3.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gdb-debuginfo-8.3.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gdb-debugsource-8.3.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gdb-testresults-8.3.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gdbserver-8.3.1-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"gdbserver-debuginfo-8.3.1-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb / gdb-debuginfo / gdb-debugsource / gdb-testresults / gdbserver / etc");
}
