#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2595.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131538);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/09");

  script_cve_id("CVE-2019-12625", "CVE-2019-12900");

  script_name(english:"openSUSE Security Update : clamav (openSUSE-2019-2595)");
  script_summary(english:"Check for the openSUSE-2019-2595 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for clamav fixes the following issues :

Security issue fixed :

  - CVE-2019-12625: Fixed a ZIP bomb issue by adding
    detection and heuristics for zips with overlapping files
    (bsc#1144504).

  - CVE-2019-12900: Fixed an out-of-bounds write in
    decompress.c with many selectors (bsc#1149458).

Non-security issues fixed :

  - Added the --max-scantime clamscan option and MaxScanTime
    clamd configuration option (bsc#1144504).

  - Increased the startup timeout of clamd to 5 minutes to
    cater for the grown virus database as a workaround until
    clamd has learned to talk to systemd to extend the
    timeout as long as needed (bsc#1151839).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1151839"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clamav-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclamav7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclamav7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclammspack0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libclammspack0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");
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

if ( rpm_check(release:"SUSE15.1", reference:"clamav-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"clamav-debuginfo-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"clamav-debugsource-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"clamav-devel-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libclamav7-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libclamav7-debuginfo-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libclammspack0-0.100.3-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libclammspack0-debuginfo-0.100.3-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav / clamav-debuginfo / clamav-debugsource / clamav-devel / etc");
}
