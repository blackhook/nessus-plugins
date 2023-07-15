#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1765.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142095);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/03");

  script_cve_id("CVE-2019-11556");

  script_name(english:"openSUSE Security Update : pagure (openSUSE-2020-1765)");
  script_summary(english:"Check for the openSUSE-2020-1765 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for pagure fixes the following issues :

  - CVE-2019-11556: Fixed XSS via the templates/blame.html
    blame view (boo#1176987)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176987"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected pagure packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-ci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-ev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-loadjson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-logcom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-milters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-theme-chameleon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-theme-default-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-theme-default-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-theme-pagureio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-theme-srcfpo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-theme-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pagure-webhook");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"pagure-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-ci-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-ev-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-loadjson-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-logcom-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-milters-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-mirror-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-theme-chameleon-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-theme-default-openSUSE-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-theme-default-upstream-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-theme-pagureio-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-theme-srcfpo-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-theme-upstream-5.5-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pagure-webhook-5.5-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pagure / pagure-ci / pagure-ev / pagure-loadjson / pagure-logcom / etc");
}
