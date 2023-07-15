#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-607.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149545);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id("CVE-2021-28965");

  script_name(english:"openSUSE Security Update : ruby2.5 (openSUSE-2021-607)");
  script_summary(english:"Check for the openSUSE-2021-607 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ruby2.5 fixes the following issues :

  - Update to 2.5.9

  - CVE-2021-28965: XML round-trip vulnerability in REXML
    (bsc#1184644)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184644"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ruby2.5 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_5-2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_5-2_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.5-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libruby2_5-2_5-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libruby2_5-2_5-debuginfo-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-debuginfo-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-debugsource-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-devel-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-devel-extra-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-doc-ri-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-stdlib-2.5.9-lp152.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"ruby2.5-stdlib-debuginfo-2.5.9-lp152.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby2_5-2_5 / libruby2_5-2_5-debuginfo / ruby2.5 / etc");
}
