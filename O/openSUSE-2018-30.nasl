#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-30.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106059);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000408", "CVE-2017-1000409", "CVE-2017-15670", "CVE-2017-15671", "CVE-2017-15804", "CVE-2017-16997", "CVE-2018-1000001");

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2018-30)");
  script_summary(english:"Check for the openSUSE-2018-30 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following issues :

  - A privilege escalation bug in the realpath() function
    has been fixed. [CVE-2018-1000001, bsc#1074293]

  - A memory leak and a buffer overflow in the dynamic ELF
    loader has been fixed. [CVE-2017-1000408,
    CVE-2017-1000409, bsc#1071319]

  - An issue in the code handling RPATHs was fixed that
    could have been exploited by an attacker to execute code
    loaded from arbitrary libraries. [CVE-2017-16997,
    bsc#1073231]

  - A potential crash caused by a use-after-free bug in
    pthread_create() has been fixed. [bsc#1053188]

  - A bug that prevented users to build shared objects which
    use the optimized libmvec.so API has been fixed.
    [bsc#1070905]

  - A memory leak in the glob() function has been fixed.
    [CVE-2017-15670, CVE-2017-15671, CVE-2017-15804,
    bsc#1064569, bsc#1064580, bsc#1064583]

  - A bug that would lose the syscall error code value in
    case of crashes has been fixed. [bsc#1063675]

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1070905"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1073231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1074293"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc "realpath()" Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-obsolete-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/16");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"glibc-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-debugsource-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-devel-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-devel-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-devel-static-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-extra-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-extra-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-html-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-i18ndata-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-info-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-locale-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-locale-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-obsolete-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-obsolete-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-profile-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-utils-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-utils-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"glibc-utils-debugsource-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nscd-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nscd-debuginfo-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"glibc-utils-32bit-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.22-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-debugsource-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-devel-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-devel-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-devel-static-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-extra-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-extra-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-html-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-i18ndata-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-info-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-locale-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-locale-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-obsolete-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-obsolete-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-profile-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-utils-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-utils-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"glibc-utils-debugsource-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nscd-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nscd-debuginfo-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-devel-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-locale-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-profile-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-utils-32bit-2.22-10.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"glibc-utils-debuginfo-32bit-2.22-10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc-utils / glibc-utils-32bit / glibc-utils-debuginfo / etc");
}
