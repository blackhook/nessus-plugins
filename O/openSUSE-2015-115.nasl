#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-115.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81241);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-1380", "CVE-2015-1381", "CVE-2015-1382");

  script_name(english:"openSUSE Security Update : privoxy (openSUSE-2015-115)");
  script_summary(english:"Check for the openSUSE-2015-115 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"privoxy was updated to version 3.0.23 to fix three security issues.

These security issues were fixed :

  - Fixed a DoS issue in case of client requests with
    incorrect chunk-encoded body. When compiled with
    assertions enabled (the default) they could previously
    cause Privoxy to abort() (CVE-2015-1380).

  - Fixed multiple segmentation faults and memory leaks in
    the pcrs code. This fix also increases the chances that
    an invalid pcrs command is rejected as such
    (CVE-2015-1381).

  - Client requests with body that can't be delivered no
    longer cause pipelined requests behind them to be
    rejected as invalid (CVE-2015-1382)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914934"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected privoxy packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:privoxy-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"privoxy-3.0.23-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"privoxy-debuginfo-3.0.23-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"privoxy-debugsource-3.0.23-2.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"privoxy-3.0.23-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"privoxy-debuginfo-3.0.23-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"privoxy-debugsource-3.0.23-8.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "privoxy / privoxy-debuginfo / privoxy-debugsource");
}
