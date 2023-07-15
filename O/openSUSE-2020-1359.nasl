#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1359.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140372);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/21");

  script_cve_id("CVE-2020-8231");
  script_xref(name:"IAVA", value:"2020-A-0389-S");

  script_name(english:"openSUSE Security Update : curl (openSUSE-2020-1359)");
  script_summary(english:"Check for the openSUSE-2020-1359 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for curl fixes the following issues :

  - An application that performs multiple requests with
    libcurl's multi API and sets the 'CURLOPT_CONNECT_ONLY'
    option, might in rare circumstances experience that when
    subsequently using the setup connect-only transfer,
    libcurl will pick and use the wrong connection and
    instead pick another one the application has created
    since then. [bsc#1175109, CVE-2020-8231]

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175109"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8231");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:curl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcurl4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"curl-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"curl-debuginfo-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"curl-debugsource-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcurl-devel-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcurl4-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libcurl4-debuginfo-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libcurl-devel-32bit-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libcurl4-32bit-7.66.0-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libcurl4-32bit-debuginfo-7.66.0-lp152.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / curl-debugsource / libcurl-devel / libcurl4 / etc");
}
