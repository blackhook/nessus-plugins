#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-527.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(99753);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-4975", "CVE-2015-1855", "CVE-2015-3900", "CVE-2015-7551", "CVE-2016-2339");

  script_name(english:"openSUSE Security Update : ruby2.1 (openSUSE-2017-527)");
  script_summary(english:"Check for the openSUSE-2017-527 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ruby2.1 update to version 2.1.9 fixes the following issues :

Security issues fixed :

  - CVE-2016-2339: heap overflow vulnerability in the
    Fiddle::Function.new'initialize' (bsc#1018808)

  - CVE-2015-7551: Unsafe tainted string usage in Fiddle and
    DL (bsc#959495)

  - CVE-2015-3900: hostname validation does not work when
    fetching gems or making API requests (bsc#936032)

  - CVE-2015-1855: Ruby'a OpenSSL extension suffers a
    vulnerability through overly permissive matching of
    hostnames (bsc#926974)

  - CVE-2014-4975: off-by-one stack-based buffer overflow in
    the encodes() function (bsc#887877)

Bugfixes :

  - SUSEconnect doesn't handle domain wildcards in no_proxy
    environment variable properly (bsc#1014863)

  - Segmentation fault after pack & ioctl & unpack
    (bsc#909695)

  - Ruby:HTTP Header injection in 'net/http' (bsc#986630)

ChangeLog :

- http://svn.ruby-lang.org/repos/ruby/tags/v2_1_9/ChangeLog

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_1_9/ChangeLog"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1014863"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1018808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=887877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=936032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986630"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ruby2.1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_1-2_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libruby2_1-2_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-devel-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby2.1-stdlib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"libruby2_1-2_1-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libruby2_1-2_1-debuginfo-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-debuginfo-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-debugsource-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-devel-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-devel-extra-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-doc-ri-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-stdlib-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ruby2.1-stdlib-debuginfo-2.1.9-10.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libruby2_1-2_1-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libruby2_1-2_1-debuginfo-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-debuginfo-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-debugsource-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-devel-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-devel-extra-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-doc-ri-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-stdlib-2.1.9-8.3.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"ruby2.1-stdlib-debuginfo-2.1.9-8.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby2_1-2_1 / libruby2_1-2_1-debuginfo / ruby2.1 / etc");
}
