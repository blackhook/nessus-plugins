#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1046.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117789);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-4975", "CVE-2016-8743");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2018-1046)");
  script_summary(english:"Check for the openSUSE-2018-1046 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apache2 fixes the following issues :

Security issues fixed :

  - CVE-2016-8743: Fixed liberal whitespace interpretation
    accepted from requests and sent in response lines and
    headers. Accepting these different behaviors represented
    a security concern when httpd participates in any chain
    of proxies or interacts with back-end application
    servers, either through mod_proxy or using conventional
    CGI mechanisms, and may result in request smuggling,
    response splitting and cache pollution. (bsc#1016715)

  - CVE-2016-4975: Fixed possible CRLF injection allowing
    HTTP response splitting attacks for sites which use
    mod_userdir. This issue was mitigated by changes which
    prohibit CR or LF injection into the 'Location' or other
    outbound header key or value. (bsc#1104826) This update
    was imported from the SUSE:SLE-12-SP2:Update update
    project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104826"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/27");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"apache2-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-debuginfo-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-debugsource-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-devel-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-event-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-event-debuginfo-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-example-pages-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-prefork-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-prefork-debuginfo-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-utils-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-utils-debuginfo-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-worker-2.4.23-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-worker-debuginfo-2.4.23-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
