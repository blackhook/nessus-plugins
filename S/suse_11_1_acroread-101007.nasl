#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update acroread-3275.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49824);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2010-2883",
    "CVE-2010-2884",
    "CVE-2010-2887",
    "CVE-2010-2889",
    "CVE-2010-2890",
    "CVE-2010-3619",
    "CVE-2010-3620",
    "CVE-2010-3621",
    "CVE-2010-3622",
    "CVE-2010-3623",
    "CVE-2010-3624",
    "CVE-2010-3625",
    "CVE-2010-3626",
    "CVE-2010-3627",
    "CVE-2010-3628",
    "CVE-2010-3629",
    "CVE-2010-3630",
    "CVE-2010-3631",
    "CVE-2010-3632",
    "CVE-2010-3656",
    "CVE-2010-3657",
    "CVE-2010-3658"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"openSUSE Security Update : acroread (openSUSE-SU-2010:0706-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Specially crafted PDF documents could crash acroread or lead to
execution of arbitrary code (CVE-2010-2883, CVE-2010-2884,
CVE-2010-2887, CVE-2010-2889, CVE-2010-2890, CVE-2010-3619,
CVE-2010-3620, CVE-2010-3621, CVE-2010-3622, CVE-2010-3623,
CVE-2010-3624, CVE-2010-3625, CVE-2010-3626, CVE-2010-3627,
CVE-2010-3628, CVE-2010-3629, CVE-2010-3630, CVE-2010-3631,
CVE-2010-3632, CVE-2010-3656, CVE-2010-3657, CVE-2010-3658).");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=638466");
  script_set_attribute(attribute:"see_also", value:"https://lists.opensuse.org/opensuse-updates/2010-10/msg00005.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected acroread packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe CoolType SING Table "uniqueName" Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-971");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-cmaps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acroread-fonts-zh_TW");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686)$") audit(AUDIT_ARCH_NOT, "i586 / i686", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"acroread-9.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acroread-cmaps-9.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acroread-fonts-ja-9.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acroread-fonts-ko-9.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acroread-fonts-zh_CN-9.4-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acroread-fonts-zh_TW-9.4-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread / acroread-cmaps / acroread-fonts-ja / acroread-fonts-ko / etc");
}
