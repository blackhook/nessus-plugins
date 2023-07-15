#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-469.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148141);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-27840", "CVE-2021-20277");
  script_xref(name:"IAVA", value:"2021-A-0140-S");

  script_name(english:"openSUSE Security Update : ldb (openSUSE-2021-469)");
  script_summary(english:"Check for the openSUSE-2021-469 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ldb fixes the following issues :

  - CVE-2020-27840: Fixed an unauthenticated remote heap
    corruption via bad DNs (bsc#1183572).

  - CVE-2021-20277: Fixed an out of bounds read in
    ldb_handler_fold (bsc#1183574).

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1183574"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ldb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20277");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ldb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libldb2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/26");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"ldb-debugsource-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ldb-tools-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ldb-tools-debuginfo-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldb-devel-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldb2-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libldb2-debuginfo-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-ldb-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-ldb-debuginfo-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-ldb-devel-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libldb2-32bit-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libldb2-32bit-debuginfo-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"python3-ldb-32bit-2.0.12-lp152.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"python3-ldb-32bit-debuginfo-2.0.12-lp152.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ldb-debugsource / ldb-tools / ldb-tools-debuginfo / libldb-devel / etc");
}
