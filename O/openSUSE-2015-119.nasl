#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-119.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81252);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141");

  script_name(english:"openSUSE Security Update : unzip (openSUSE-2015-119)");
  script_summary(english:"Check for the openSUSE-2015-119 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"unzip was updated to fix security issues.

The unzip command line tool is affected by heap-based buffer overflows
within the CRC32 verification (CVE-2014-8139), the test_compr_eb()
(CVE-2014-8140) and the getZip64Data() functions (CVE-2014-8141). The
input errors may result in in arbitrary code execution.

More info can be found in the oCert announcement:
http://seclists.org/oss-sec/2014/q4/1127"
  );
  # http://seclists.org/oss-sec/2014/q4/1127
  script_set_attribute(
    attribute:"see_also",
    value:"https://seclists.org/oss-sec/2014/q4/1127"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909214"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unzip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-rcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-rcc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:unzip-rcc-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"unzip-6.00-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"unzip-debuginfo-6.00-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"unzip-debugsource-6.00-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"unzip-rcc-6.00-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"unzip-rcc-debuginfo-6.00-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"unzip-rcc-debugsource-6.00-24.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-6.00-26.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-debuginfo-6.00-26.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-debugsource-6.00-26.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-rcc-6.00-26.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-rcc-debuginfo-6.00-26.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"unzip-rcc-debugsource-6.00-26.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unzip-rcc / unzip-rcc-debuginfo / unzip-rcc-debugsource / unzip / etc");
}
