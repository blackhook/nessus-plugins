#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2333.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145389);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/14");

  script_cve_id("CVE-2019-16935", "CVE-2019-18348", "CVE-2019-20907", "CVE-2019-5010", "CVE-2020-14422", "CVE-2020-26116", "CVE-2020-27619", "CVE-2020-8492");

  script_name(english:"openSUSE Security Update : python3 (openSUSE-2020-2333)");
  script_summary(english:"Check for the openSUSE-2020-2333 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python3 fixes the following issues :

  - Fixed CVE-2020-27619 (bsc#1178009), where
    Lib/test/multibytecodec_support calls eval() on content
    retrieved via HTTP.

  - Change setuptools and pip version numbers according to
    new wheels

  - Handful of changes to make python36 compatible with
    SLE15 and SLE12 (jsc#ECO-2799, jsc#SLE-13738)

  - add triplets for mips-r6 and riscv

  - RISC-V needs CTYPES_PASS_BY_REF_HACK

Update to 3.6.12 (bsc#1179193)

  - Ensure python3.dll is loaded from correct locations when
    Python is embedded

  - The __hash__() methods of ipaddress.IPv4Interface and
    ipaddress.IPv6Interface incorrectly generated constant
    hash values of 32 and 128 respectively. This resulted in
    always causing hash collisions. The fix uses hash() to
    generate hash values for the tuple of (address, mask
    length, network address).

  - Prevent http header injection by rejecting control
    characters in http.client.putrequest(&hellip;).

  - Unpickling invalid NEWOBJ_EX opcode with the C
    implementation raises now UnpicklingError instead of
    crashing.

  - Avoid infinite loop when reading specially crafted TAR
    files using the tarfile module

  - This release also fixes CVE-2020-26116 (bsc#1177211) and
    CVE-2019-20907 (bsc#1174091).

Update to 3.6.11 :

  - Disallow CR or LF in email.headerregistry. Address
    arguments to guard against header injection attacks.

  - Disallow control characters in hostnames in http.client,
    addressing CVE-2019-18348. Such potentially malicious
    header injection URLs now cause a InvalidURL to be
    raised. (bsc#1155094)

  - CVE-2020-8492: The AbstractBasicAuthHandler class of the
    urllib.request module uses an inefficient regular
    expression which can be exploited by an attacker to
    cause a denial of service. Fix the regex to prevent the
    catastrophic backtracking. Vulnerability reported by Ben
    Caller and Matt Schwager.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179630"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected python3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpython3_6m1_0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-core-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-curses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-dbm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-doc-devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"libpython3_6m1_0-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpython3_6m1_0-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-base-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-base-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-core-debugsource-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-curses-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-curses-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-dbm-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-dbm-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-debugsource-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-devel-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-devel-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-doc-devhelp-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-idle-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-testsuite-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-testsuite-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-tk-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-tk-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-tools-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libpython3_6m1_0-32bit-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-32bit-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-32bit-debuginfo-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-base-32bit-3.6.12-lp151.6.32.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"python3-base-32bit-debuginfo-3.6.12-lp151.6.32.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3 / python3-curses / python3-curses-debuginfo / python3-dbm / etc");
}
