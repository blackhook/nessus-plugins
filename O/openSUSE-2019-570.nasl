#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-570.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123247);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-2940", "CVE-2018-2952", "CVE-2018-2972", "CVE-2018-2973");

  script_name(english:"openSUSE Security Update : java-10-openjdk (openSUSE-2019-570)");
  script_summary(english:"Check for the openSUSE-2019-570 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for OpenJDK 10.0.2 fixes the following security issues :

  - CVE-2018-2940: the libraries sub-component contained an
    easily exploitable vulnerability that allowed attackers
    to compromise Java SE or Java SE Embedded over the
    network, potentially gaining unauthorized read access to
    data that's accessible to the server. [bsc#1101645]

  - CVE-2018-2952: the concurrency sub-component contained a
    difficult to exploit vulnerability that allowed
    attackers to compromise Java SE, Java SE Embedded, or
    JRockit over the network. This issue could have been
    abused to mount a partial denial-of-service attack on
    the server. [bsc#1101651]

  - CVE-2018-2972: the security sub-component contained a
    difficult to exploit vulnerability that allowed
    attackers to compromise Java SE over the network,
    potentially gaining unauthorized access to critical data
    or complete access to all Java SE accessible data.
    [bsc#1101655)

  - CVE-2018-2973: the JSSE sub-component contained a
    difficult to exploit vulnerability allowed attackers to
    compromise Java SE or Java SE Embedded over the network,
    potentially gaining the ability to create, delete or
    modify critical data or all Java SE, Java SE Embedded
    accessible data without authorization. [bsc#1101656]

Furthemore, the following bugs were fixed :

  - Properly remove the existing alternative for java before
    reinstalling it. [bsc#1096420]

  - idlj was moved to the *-devel package. [bsc#1096420]

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101656"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-10-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2973");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-accessibility-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-10-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-accessibility-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-accessibility-debuginfo-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-debuginfo-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-debugsource-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-demo-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-devel-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-headless-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-javadoc-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-jmods-10.0.2.0-lp150.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"java-10-openjdk-src-10.0.2.0-lp150.2.3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-10-openjdk / java-10-openjdk-accessibility / etc");
}
