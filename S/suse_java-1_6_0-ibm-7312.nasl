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
  script_id(51750);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-3555", "CVE-2010-0771", "CVE-2010-1321", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574");

  script_name(english:"SuSE 10 Security Update : IBM Java 6 SR9 (ZYPP Patch Number 7312)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Java 6 SR9 was released, fixing a lot of security issues.

IBM JDK Alerts can also be found on this page:
http://www.ibm.com/developerworks/java/jdk/alerts/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0771.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1321.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3556.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3557.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3560.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3567.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3568.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3572.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3573.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3574.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7312.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start BasicServiceImpl Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

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
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-devel-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-fonts-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"java-1_6_0-ibm-plugin-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-32bit-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-32bit-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-devel-32bit-1.6.0_sr9.0-1.4.6")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-32bit-1.6.0_sr9.0-1.4.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
