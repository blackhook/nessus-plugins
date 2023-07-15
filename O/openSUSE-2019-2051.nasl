#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2051.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(128460);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-10081",
    "CVE-2019-10082",
    "CVE-2019-10092",
    "CVE-2019-10097",
    "CVE-2019-10098",
    "CVE-2019-9517"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2019-2051) (Internal Data Buffering)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for apache2 fixes the following issues :

Security issues fixed :

  - CVE-2019-9517: Fixed HTTP/2 implementations that are
    vulnerable to unconstrained interal data buffering
    (bsc#1145575).

  - CVE-2019-10081: Fixed mod_http2 that is vulnerable to
    memory corruption on early pushes (bsc#1145742).

  - CVE-2019-10082: Fixed mod_http2 that is vulnerable to
    read-after-free in h2 connection shutdown (bsc#1145741).

  - CVE-2019-10092: Fixed limited cross-site scripting in
    mod_proxy (bsc#1145740).

  - CVE-2019-10097: Fixed mod_remoteip stack-based buffer
    overflow and NULL pointer dereference (bsc#1145739).

  - CVE-2019-10098: Fixed mod_rewrite configuration
    vulnerablility to open redirect (bsc#1145738).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1145742");
  script_set_attribute(attribute:"solution", value:
"Update the affected apache2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

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

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"apache2-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-debuginfo-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-debugsource-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-devel-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-event-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-event-debuginfo-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-example-pages-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-prefork-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-prefork-debuginfo-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-utils-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-utils-debuginfo-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-worker-2.4.33-lp151.8.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"apache2-worker-debuginfo-2.4.33-lp151.8.6.1") ) flag++;

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
