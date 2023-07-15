#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49862);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0091",
    "CVE-2010-0095",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"SuSE 10 Security Update : IBM Java (ZYPP Patch Number 7106)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"This update brings IBM Java 1.4.2 to SR13 FP5, fixing various bugs and");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0084.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0085.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0087.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0088.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0089.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0091.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0095.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0839.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0840.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0841.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0842.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0843.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0844.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0846.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0847.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0848.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2010-0849.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 7106.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_4_2-ibm-1.4.2_sr13.5-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_4_2-ibm-devel-1.4.2_sr13.5-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_4_2-ibm-jdbc-1.4.2_sr13.5-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_4_2-ibm-plugin-1.4.2_sr13.5-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
