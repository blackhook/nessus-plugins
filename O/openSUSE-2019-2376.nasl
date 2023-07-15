#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2376.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(130333);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id("CVE-2018-1122", "CVE-2018-1123", "CVE-2018-1124", "CVE-2018-1125", "CVE-2018-1126");

  script_name(english:"openSUSE Security Update : procps (openSUSE-2019-2376)");
  script_summary(english:"Check for the openSUSE-2019-2376 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for procps fixes the following issues :

procps was updated to 3.3.15. (bsc#1092100)

Following security issues were fixed :

  - CVE-2018-1122: Prevent local privilege escalation in
    top. If a user ran top with HOME unset in an
    attacker-controlled directory, the attacker could have
    achieved privilege escalation by exploiting one of
    several vulnerabilities in the config_file() function
    (bsc#1092100).

  - CVE-2018-1123: Prevent denial of service in ps via mmap
    buffer overflow. Inbuilt protection in ps maped a guard
    page at the end of the overflowed buffer, ensuring that
    the impact of this flaw is limited to a crash (temporary
    denial of service) (bsc#1092100).

  - CVE-2018-1124: Prevent multiple integer overflows
    leading to a heap corruption in file2strvec function.
    This allowed a privilege escalation for a local attacker
    who can create entries in procfs by starting processes,
    which could result in crashes or arbitrary code
    execution in proc utilities run by other users
    (bsc#1092100).

  - CVE-2018-1125: Prevent stack-based buffer overflow in
    pgrep. This vulnerability was mitigated by FORTIFY
    limiting the impact to a crash (bsc#1092100).

  - CVE-2018-1126: Ensure correct integer size in
    proc/alloc.* to prevent truncation/integer overflow
    issues (bsc#1092100).

Also this non-security issue was fixed :

  - Fix CPU summary showing old data. (bsc#1121753)

The update to 3.3.15 contains the following fixes :

  - library: Increment to 8:0:1 No removals, no new
    functions Changes: slab and pid structures

  - library: Just check for SIGLOST and don't delete it

  - library: Fix integer overflow and LPE in file2strvec
    CVE-2018-1124

  - library: Use size_t for alloc functions CVE-2018-1126

  - library: Increase comm size to 64

  - pgrep: Fix stack-based buffer overflow CVE-2018-1125

  - pgrep: Remove >15 warning as comm can be longer

  - ps: Fix buffer overflow in output buffer, causing DOS
    CVE-2018-1123

  - ps: Increase command name selection field to 64

  - top: Don't use cwd for location of config CVE-2018-1122

  - update translations

  - library: build on non-glibc systems

  - free: fix scaling on 32-bit systems

  - Revert 'Support running with child namespaces'

  - library: Increment to 7:0:1 No changes, no removals New
    fuctions: numa_init, numa_max_node, numa_node_of_cpu,
    numa_uninit, xalloc_err_handler

  - doc: Document I idle state in ps.1 and top.1

  - free: fix some of the SI multiples

  - kill: -l space between name parses correctly

  - library: dont use vm_min_free on non Linux

  - library: don't strip off wchan prefixes (ps & top)

  - pgrep: warn about 15+ char name only if -f not used

  - pgrep/pkill: only match in same namespace by default

  - pidof: specify separator between pids

  - pkill: Return 0 only if we can kill process

  - pmap: fix duplicate output line under '-x' option

  - ps: avoid eip/esp address truncations

  - ps: recognizes SCHED_DEADLINE as valid CPU scheduler

  - ps: display NUMA node under which a thread ran

  - ps: Add seconds display for cputime and time

  - ps: Add LUID field

  - sysctl: Permit empty string for value

  - sysctl: Don't segv when file not available

  - sysctl: Read and write large buffers

  - top: add config file support for XDG specification

  - top: eliminated minor libnuma memory leak

  - top: show fewer memory decimal places (configurable)

  - top: provide command line switch for memory scaling

  - top: provide command line switch for CPU States

  - top: provides more accurate cpu usage at startup

  - top: display NUMA node under which a thread ran

  - top: fix argument parsing quirk resulting in SEGV

  - top: delay interval accepts non-locale radix point

  - top: address a wishlist man page NLS suggestion

  - top: fix potential distortion in 'Mem' graph display

  - top: provide proper multi-byte string handling

  - top: startup defaults are fully customizable

  - watch: define HOST_NAME_MAX where not defined

  - vmstat: Fix alignment for disk partition format

  - watch: Support ANSI 39,49 reset sequences

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121753"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected procps packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libprocps7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libprocps7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procps-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procps-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/28");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libprocps7-3.3.15-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libprocps7-debuginfo-3.3.15-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"procps-3.3.15-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"procps-debuginfo-3.3.15-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"procps-debugsource-3.3.15-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"procps-devel-3.3.15-lp151.6.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libprocps7 / libprocps7-debuginfo / procps / procps-debuginfo / etc");
}
