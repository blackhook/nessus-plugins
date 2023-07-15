#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-539.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110214);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-3152", "CVE-2017-10788", "CVE-2017-10789");

  script_name(english:"openSUSE Security Update : perl-DBD-mysql (openSUSE-2018-539) (BACKRONYM)");
  script_summary(english:"Check for the openSUSE-2018-539 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for perl-DBD-mysql fixes the following issues :

  - CVE-2017-10789: The DBD::mysql module when with
    mysql_ssl=1 setting enabled, means that SSL is optional
    (even though this setting's documentation has a \'your
    communication with the server will be encrypted\'
    statement), which could lead man-in-the-middle attackers
    to spoof servers via a cleartext-downgrade attack, a
    related issue to CVE-2015-3152. (bsc#1047059)

  - CVE-2017-10788: The DBD::mysql module through 4.043 for
    Perl allows remote attackers to cause a denial of
    service (use-after-free and application crash) or
    possibly have unspecified other impact by triggering (1)
    certain error responses from a MySQL server or (2) a
    loss of a network connection to a MySQL server. The
    use-after-free defect was introduced by relying on
    incorrect Oracle mysql_stmt_close documentation and code
    examples. (bsc#1047095)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-DBD-mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-DBD-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-DBD-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-DBD-mysql-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"perl-DBD-mysql-4.021-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-DBD-mysql-debuginfo-4.021-18.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-DBD-mysql-debugsource-4.021-18.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-DBD-mysql / perl-DBD-mysql-debuginfo / etc");
}
