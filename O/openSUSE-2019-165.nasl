#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-165.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122178);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-19198", "CVE-2018-19199", "CVE-2018-19200", "CVE-2018-20721");

  script_name(english:"openSUSE Security Update : uriparser (openSUSE-2019-165)");
  script_summary(english:"Check for the openSUSE-2019-165 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for uriparser fixes the following issues :

Security issues fixed :

  - CVE-2018-20721: Fixed an out-of-bounds read for
    incomplete URIs with IPv6 addresses with embedded IPv4
    address (bsc#1122193).

  - CVE-2018-19198: Fixed an out-of-bounds write that was
    possible via the uriComposeQuery* or uriComposeQueryEx*
    function (bsc#1115722).

  - CVE-2018-19199: Fixed an integer overflow caused by an
    unchecked multiplication via the uriComposeQuery* or
    uriComposeQueryEx* function (bsc#1115723).

  - CVE-2018-19200: Fixed a operation attempted on NULL
    input via a uriResetUri* function (bsc#1115724).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122193"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected uriparser packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liburiparser1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liburiparser1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liburiparser1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liburiparser1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uriparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uriparser-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uriparser-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uriparser-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"liburiparser1-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"liburiparser1-debuginfo-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"uriparser-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"uriparser-debuginfo-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"uriparser-debugsource-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"uriparser-devel-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"liburiparser1-32bit-0.8.5-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"liburiparser1-32bit-debuginfo-0.8.5-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "liburiparser1 / liburiparser1-32bit / liburiparser1-32bit-debuginfo / etc");
}
