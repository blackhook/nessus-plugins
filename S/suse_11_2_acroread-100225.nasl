#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update acroread-2068.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44981);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id("CVE-2010-0186", "CVE-2010-0188");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"openSUSE Security Update : acroread (acroread-2068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update of acroread fixes :

  - CVE-2010-0186: CVSS v2 Base Score: 5.8 Cross-domain
    request vulnerability

  - CVE-2010-0188: CVSS v2 Base Score: 6.8 An unspecified
    vulnerability that possibly allowed remote code
    execution.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=580470");
  script_set_attribute(attribute:"solution", value:
"Update the affected acroread packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Acrobat Bundled LibTIFF Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(94);

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"acroread-9.3.1-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-cmaps-9.3.1-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-ja-9.3.1-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-ko-9.3.1-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-zh_CN-9.3.1-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"acroread-fonts-zh_TW-9.3.1-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread");
}
