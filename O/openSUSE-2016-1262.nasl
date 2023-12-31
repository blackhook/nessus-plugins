#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1262.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94531);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-4912", "CVE-2016-7567");

  script_name(english:"openSUSE Security Update : openslp (openSUSE-2016-1262)");
  script_summary(english:"Check for the openSUSE-2016-1262 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openslp fixes two security issues and two bugs.

The following vulnerabilities were fixed :

  - CVE-2016-4912: A remote attacker could have crashed the
    server with a large number of packages (bsc#980722)

  - CVE-2016-7567: A remote attacker could cause a memory
    corruption having unspecified impact (bsc#1001600)

The following bugfix changes are included :

  - bsc#994989: Removed convenience code as changes bytes in
    the message buffer breaking the verification code

  - bsc#974655: Removed no longer needed slpd init file

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994989"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openslp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openslp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"openslp-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openslp-debuginfo-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openslp-debugsource-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openslp-devel-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openslp-server-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"openslp-server-debuginfo-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"openslp-32bit-2.0.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"openslp-debuginfo-32bit-2.0.0-17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openslp / openslp-32bit / openslp-debuginfo / etc");
}
