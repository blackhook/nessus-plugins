#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1269.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104527);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10165", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295", "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348", "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356", "CVE-2017-10357", "CVE-2017-10388");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2017-1269)");
  script_summary(english:"Check for the openSUSE-2017-1269 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk fixes the following issues :

  - Update to version jdk8u151 (icedtea 3.6.0)

Security issues fixed :

  - CVE-2017-10274: Handle smartcard clean up better
    (bsc#1064071)

  - CVE-2017-10281: Better queuing priorities (bsc#1064072)

  - CVE-2017-10285: Unreferenced references (bsc#1064073)

  - CVE-2017-10295: Better URL connections (bsc#1064075)

  - CVE-2017-10388: Correct Kerberos ticket grants
    (bsc#1064086)

  - CVE-2017-10346: Better invokespecial checks
    (bsc#1064078)

  - CVE-2017-10350: Better Base Exceptions (bsc#1064082)

  - CVE-2017-10347: Better timezone processing (bsc#1064079)

  - CVE-2017-10349: Better X processing (bsc#1064081)

  - CVE-2017-10345: Better keystore handling (bsc#1064077)

  - CVE-2017-10348: Better processing of unresolved
    permissions (bsc#1064080)

  - CVE-2017-10357: Process Proxy presentation (bsc#1064085)

  - CVE-2017-10355: More stable connection processing
    (bsc#1064083)

  - CVE-2017-10356: Update storage implementations
    (bsc#1064084)

  - CVE-2016-10165: Improve CMS header processing
    (bsc#1064069)

  - CVE-2016-9840, CVE-2016-9841, CVE-2016-9842,
    CVE-2016-9843: Upgrade compression library (bsc#1064070)

Bug fixes :

  - Fix bsc#1032647, bsc#1052009 with btrfs subvolumes and
    overlayfs

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064086"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.151-10.18.2") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-accessibility-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-debugsource-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-demo-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-devel-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-headless-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-javadoc-1.8.0.151-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"java-1_8_0-openjdk-src-1.8.0.151-18.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
