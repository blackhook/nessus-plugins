#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-375.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109101);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-7158", "CVE-2018-7159");

  script_name(english:"openSUSE Security Update : nodejs4 (openSUSE-2018-375)");
  script_summary(english:"Check for the openSUSE-2018-375 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs4 fixes the following issues :

  - Fix some node-gyp permissions

  - New upstream maintenance 4.9.1 :

  - Security fixes :

  + CVE-2018-7158: Fix for 'path' module regular expression
    denial of service (bsc#1087459)

  + CVE-2018-7159: Reject spaces in HTTP Content-Length
    header values (bsc#1087453)

  - Upgrade to OpenSSL 1.0.2o

  - deps: reject interior blanks in Content-Length

  - deps: upgrade http-parser to v2.8.0

  - remove any old manpage files in %pre from before
    update-alternatives were used to manage symlinks to
    these manpages.

  - Add Recommends and BuildRequire on python2 for npm.
    node-gyp requires this old version of python for now.
    This is only needed for binary modules.

  - even on recent codestreams there is no binutils gold on
    s390 only on s390x

  - Enable CI tests in %check target This update was
    imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087459"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs4 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");
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

if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-4.9.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-debuginfo-4.9.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-debugsource-4.9.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-devel-4.9.1-14.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"npm4-4.9.1-14.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs4 / nodejs4-debuginfo / nodejs4-debugsource / nodejs4-devel / etc");
}
