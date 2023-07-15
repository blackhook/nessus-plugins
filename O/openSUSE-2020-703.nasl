#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-703.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(136886);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2018-10886");

  script_name(english:"openSUSE Security Update : ant (openSUSE-2020-703)");
  script_summary(english:"Check for the openSUSE-2020-703 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for ant fixes the following issues :

Security issue fixed :

  - CVE-2018-10886: Fixed a path traversal vulnerability in
    malformed zip file paths, which allowed arbitrary file
    writes and could potentially lead to code execution
    (bsc#1100053). 

Non-security issues fixed :

  - Add rhino to the ant-apache-bsf optional tasks
    (bsc#1134001).

  - Remove jakarta-commons-logging dependencies
    (bsc#1133997).

  - Use apache-commons-logging in optional tasks

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1134001"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ant packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10886");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-apache-xalan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-commons-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-jdepend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-jmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-jsch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-swing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ant-testutil");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

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



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"ant-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-antlr-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-bcel-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-bsf-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-log4j-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-oro-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-regexp-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-resolver-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-apache-xalan2-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-commons-logging-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-commons-net-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-javamail-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-jdepend-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-jmf-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-jsch-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-junit-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-manual-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-scripts-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-swing-1.9.10-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ant-testutil-1.9.10-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ant-antlr / ant-apache-bcel / ant-apache-bsf / ant-apache-log4j / etc");
}
