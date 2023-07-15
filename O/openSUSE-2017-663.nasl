#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-663.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100708);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-1839", "CVE-2017-9047", "CVE-2017-9048", "CVE-2017-9049", "CVE-2017-9050");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2017-663)");
  script_summary(english:"Check for the openSUSE-2017-663 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libxml2 fixes the following issues :

  - CVE-2017-9047, CVE-2017-9048: The function
    xmlSnprintfElementContent in valid.c was vulnerable to a
    stack-based buffer overflow (bsc#1039063, bsc#1039064)

  - CVE-2017-9049: The function xmlDictComputeFastKey in
    dict.c was vulnerable to a heap-based buffer over-read.
    (bsc#1039066)

  - CVE-2017-9050: The function xmlDictAddString was
    vulnerable to a heap-based buffer over-read
    (bsc#1039661)

  - CVE-2016-1839: heap-based buffer overflow
    (xmlDictAddString func) (bnc#1039069)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981114"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxml2-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-libxml2-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"libxml2-2-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxml2-2-debuginfo-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxml2-debugsource-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxml2-devel-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxml2-tools-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libxml2-tools-debuginfo-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-libxml2-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-libxml2-debuginfo-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-libxml2-debugsource-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libxml2-2-debuginfo-32bit-2.9.4-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.4-5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-32bit / libxml2-2-debuginfo / etc");
}
