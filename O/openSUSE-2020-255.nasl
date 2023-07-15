#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-255.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(134156);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/06");

  script_cve_id("CVE-2019-18900");

  script_name(english:"openSUSE Security Update : libsolv / libzypp / zypper (openSUSE-2020-255)");
  script_summary(english:"Check for the openSUSE-2020-255 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libsolv, libzypp, zypper fixes the following issues :

Security issue fixed :

  - CVE-2019-18900: Fixed assert cookie file that was world
    readable (bsc#1158763).

Bug fixes

  - Fixed removing orphaned packages dropped by
    to-be-installed products (bsc#1155819).

  - Adds libzypp API to mark all obsolete kernels according
    to the existing purge-kernel script rules (bsc#1155198).

  - Do not enforce 'en' being in RequestedLocales If the
    user decides to have a system without explicit language
    support he may do so (bsc#1155678). 

  - Load only target resolvables for zypper rm
    (bsc#1157377).

  - Fix broken search by filelist (bsc#1135114).

  - Replace python by a bash script in zypper-log
    (fixes#304, fixes#306, bsc#1156158).

  - Do not sort out requested locales which are not
    available (bsc#1155678).

  - Prevent listing duplicate matches in tables. XML result
    is provided within the new list-patches-byissue element
    (bsc#1154805). 

  - XML add patch issue-date and issue-list (bsc#1154805).

  - Fix zypper lp --cve/bugzilla/issue options
    (bsc#1155298).

  - Always execute commit when adding/removing locales
    (fixes bsc#1155205).

  - Fix description of --table-style,-s in man page
    (bsc#1154804).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1135114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1157377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1158763"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libsolv / libzypp / zypper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsolv-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libzypp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-solv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-aptitude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zypper-needs-restarting");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libsolv-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-debugsource-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-demo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-demo-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-devel-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-devel-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-tools-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsolv-tools-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzypp-17.19.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzypp-debuginfo-17.19.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzypp-debugsource-17.19.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libzypp-devel-17.19.0-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-solv-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"perl-solv-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-solv-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python-solv-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-solv-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-solv-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby-solv-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ruby-solv-debuginfo-0.7.10-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zypper-1.14.33-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zypper-aptitude-1.14.33-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zypper-debuginfo-1.14.33-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zypper-debugsource-1.14.33-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zypper-log-1.14.33-lp151.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zypper-needs-restarting-1.14.33-lp151.2.10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsolv-debuginfo / libsolv-debugsource / libsolv-demo / etc");
}
