#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1358.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105241);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10253", "CVE-2017-1000385");

  script_name(english:"openSUSE Security Update : erlang (openSUSE-2017-1358) (ROBOT)");
  script_summary(english:"Check for the openSUSE-2017-1358 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for erlang fixes security issues and bugs.

The following vulnerabilities were addressed :

  - CVE-2017-1000385: Harden against the Bleichenbacher
    attacher against RSA 

  - CVE-2016-10253: Heap overflow through regular
    expressions (bsc#1030062)

In addition Erlang was updated to version 18.3.4.6, containing a
number of upstream bug fixes and improvements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected erlang packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debugger-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-dialyzer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-dialyzer-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-diameter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-diameter-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-epmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-epmd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-et-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-gs-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-jinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-jinterface-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-observer-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-reltool-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-wx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-wx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-wx-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"erlang-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-debugger-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-debugger-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-debuginfo-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-debugsource-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-dialyzer-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-dialyzer-debuginfo-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-dialyzer-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-diameter-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-diameter-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-epmd-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-epmd-debuginfo-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-et-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-et-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-gs-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-gs-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-jinterface-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-jinterface-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-observer-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-observer-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-reltool-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-reltool-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-wx-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-wx-debuginfo-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"erlang-wx-src-18.3.4.7-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-debugger-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-debugger-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-debuginfo-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-debugsource-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-dialyzer-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-dialyzer-debuginfo-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-dialyzer-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-diameter-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-diameter-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-epmd-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-epmd-debuginfo-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-et-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-et-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-gs-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-gs-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-jinterface-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-jinterface-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-observer-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-observer-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-reltool-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-reltool-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-src-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-wx-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-wx-debuginfo-18.3.4.7-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"erlang-wx-src-18.3.4.7-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "erlang / erlang-debugger / erlang-debugger-src / erlang-debuginfo / etc");
}
