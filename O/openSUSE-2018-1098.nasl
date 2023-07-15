#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1098.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117929);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-17144");

  script_name(english:"openSUSE Security Update : bitcoin (openSUSE-2018-1098)");
  script_summary(english:"Check for the openSUSE-2018-1098 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bitcoin to version 0.16.3 fixes the following issues :

  - CVE-2018-17144: Prevent remote denial of service
    (application crash) exploitable by miners via duplicate
    input (bsc#1108992).

For additional changes please check the changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1108992"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bitcoin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-qt5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoin-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bitcoind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbitcoinconsensus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbitcoinconsensus0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbitcoinconsensus0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/05");
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
if (release !~ "^(SUSE15\.0|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-debuginfo-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-debugsource-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-qt5-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-qt5-debuginfo-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-test-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-test-debuginfo-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-utils-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoin-utils-debuginfo-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoind-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"bitcoind-debuginfo-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libbitcoinconsensus-devel-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libbitcoinconsensus0-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libbitcoinconsensus0-debuginfo-0.16.3-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-debugsource-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-qt5-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-qt5-debuginfo-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-test-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-test-debuginfo-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-utils-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoin-utils-debuginfo-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoind-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"bitcoind-debuginfo-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libbitcoinconsensus-devel-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libbitcoinconsensus0-0.16.3-7.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libbitcoinconsensus0-debuginfo-0.16.3-7.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bitcoin-debuginfo / bitcoin-debugsource / bitcoin-qt5 / etc");
}
