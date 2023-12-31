#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51697);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id("CVE-2010-0186", "CVE-2010-0188");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"SuSE 10 Security Update : Acrobat Reader (ZYPP Patch Number 6879)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"This update of acroread fixes :

  - Cross-domain request vulnerability CVE-2010-0188: CVSS
    v2 Base Score: 6.8 An unspecified vulnerability that
    possibly allowed remote code execution. (CVE-2010-0186:
    CVSS v2 Base Score: 5.8)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0186.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0188.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 6879.");
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
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:2, reference:"acroread-9.3.1-0.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"acroread-cmaps-9.3.1-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"acroread-fonts-ja-9.3.1-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"acroread-fonts-ko-9.3.1-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"acroread-fonts-zh_CN-9.3.1-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"acroread-fonts-zh_TW-9.3.1-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
