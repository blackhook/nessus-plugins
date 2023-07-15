#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-597.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136310);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1927", "CVE-2020-1934", "CVE-2020-1938");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2020-597)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for apache2 fixes the following issues :

  - CVE-2020-1934: mod_proxy_ftp may use uninitialized
    memory when proxying to a malicious FTP server
    (bsc#1168404).

  - CVE-2020-1927: mod_rewrite configurations vulnerable to
    open redirect (bsc#1168407).

  - CVE-2020-1938: mod_proxy_ajp: Add 'secret' parameter to
    proxy workers to implement legacy AJP13 authentication
    (bsc#1169066).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168404");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1168407");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169066");
  script_set_attribute(attribute:"solution", value:
"Update the affected apache2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"apache2-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-debuginfo-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-debugsource-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-devel-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-event-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-event-debuginfo-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-example-pages-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-prefork-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-prefork-debuginfo-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-utils-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-utils-debuginfo-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-worker-2.4.33-lp151.8.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-worker-debuginfo-2.4.33-lp151.8.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
