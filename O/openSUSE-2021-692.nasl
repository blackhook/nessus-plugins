#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-692.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149571);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2021-3516", "CVE-2021-3517", "CVE-2021-3518");

  script_name(english:"openSUSE Security Update : libxml2 (openSUSE-2021-692)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libxml2 fixes the following issues :

  - CVE-2021-3518: Fixed a use after free in
    xinclude.c:xmlXIncludeDoProcess (bsc#1185408).

  - CVE-2021-3517: Fixed a heap based buffer overflow in
    entities.c:xmlEncodeEntitiesInternal (bsc#1185410).

  - CVE-2021-3516: Fixed a use after free in
    entities.c:xmlEncodeEntitiesInternal (bsc#1185409).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185410");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxml2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libxml2-2-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libxml2-2-debuginfo-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libxml2-debugsource-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libxml2-devel-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libxml2-tools-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libxml2-tools-debuginfo-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python-libxml2-python-debugsource-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python2-libxml2-python-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python2-libxml2-python-debuginfo-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-libxml2-python-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-libxml2-python-debuginfo-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libxml2-2-32bit-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libxml2-2-32bit-debuginfo-2.9.7-lp152.10.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libxml2-devel-32bit-2.9.7-lp152.10.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxml2-2 / libxml2-2-debuginfo / libxml2-debugsource / etc");
}
