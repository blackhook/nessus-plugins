#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-785.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123336);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14404", "CVE-2018-14567", "CVE-2018-9251");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2019-785)");
  script_summary(english:"Check for the openSUSE-2019-785 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxml2 fixes the following security issues :

  - CVE-2018-9251: The xz_decomp function allowed remote
    attackers to cause a denial of service (infinite loop)
    via a crafted XML file that triggers
    LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint
    (bsc#1088279)

  - CVE-2018-14567: Prevent denial of service (infinite
    loop) via a crafted XML file that triggers
    LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint
    (bsc#1105166)

  - CVE-2018-14404: Prevent NULL pointer dereference in the
    xmlXPathCompOpEval() function when parsing an invalid
    XPath expression in the XPATH_OP_AND or XPATH_OP_OR case
    leading to a denial of service attack (bsc#1102046)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105166"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libxml2-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/04");
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

if ( rpm_check(release:"SUSE15.0", reference:"libxml2-2-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxml2-2-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxml2-debugsource-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxml2-devel-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxml2-tools-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libxml2-tools-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python-libxml2-python-debugsource-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-libxml2-python-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python2-libxml2-python-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-libxml2-python-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-libxml2-python-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.7-lp150.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-32bit / libxml2-2-32bit-debuginfo / etc");
}
