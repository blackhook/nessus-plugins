#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111587);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-18248", "CVE-2018-4180", "CVE-2018-4181", "CVE-2018-4182", "CVE-2018-4183");

  script_name(english:"openSUSE Security Update : cups (openSUSE-2018-822)");
  script_summary(english:"Check for the openSUSE-2018-822 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cups fixes the following issues :

The following security vulnerabilities were fixed :

  - CVE-2017-18248: Handle invalid characters properly in
    printing jobs. This fixes a problem that was causing the
    DBUS library to abort the calling process. (bsc#1061066
    bsc#1087018)

  - Fixed a local privilege escalation to root and sandbox
    bypasses in the scheduler

  - CVE-2018-4180: Fixed a local privilege escalation to
    root in dnssd backend (bsc#1096405)

  - CVE-2018-4181: Limited local file reads as root via
    cupsd.conf include directive (bsc#1096406)

  - CVE-2018-4182: Fixed a sandbox bypass due to insecure
    error handling (bsc#1096407)

  - CVE-2018-4183: Fixed a sandbox bypass due to profile
    misconfiguration (bsc#1096408)

The following other issue was fixed :

  - Fixed authorization check for clients (like samba)
    connected through the local socket when Kerberos
    authentication is enabled (bsc#1050082)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096408"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-ddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-ddk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

if ( rpm_check(release:"SUSE42.3", reference:"cups-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-client-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-client-debuginfo-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-ddk-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-ddk-debuginfo-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-debuginfo-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-debugsource-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-devel-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-libs-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"cups-libs-debuginfo-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-libs-32bit-1.7.5-12.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"cups-libs-debuginfo-32bit-1.7.5-12.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-client-debuginfo / cups-ddk / etc");
}
