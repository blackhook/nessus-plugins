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
  script_id(69093);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2452",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3009",
    "CVE-2013-3011",
    "CVE-2013-3012",
    "CVE-2013-3743",
    "CVE-2013-4002"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"SuSE 10 Security Update : java-1_5_0-ibm (ZYPP Patch Number 8653)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"IBM Java 1.5.0 has been updated to SR16-FP3 to fix bugs and security
issues.

Please see also http://www.ibm.com/developerworks/java/jdk/alerts/

Also the following bug has been fixed :

  - add Europe/Busingen to tzmappings. (bnc#817062)

  - mark files in jre/bin and bin/ as executable
    (bnc#823034)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1500.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1571.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2443.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2444.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2446.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2447.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2448.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2450.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2452.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2454.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2455.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2456.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2457.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2459.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2463.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2464.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2465.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2469.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2470.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2471.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2472.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-2473.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-3009.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-3011.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-3012.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-3743.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-4002.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 8653.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-demo-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-devel-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-fonts-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"java-1_5_0-ibm-src-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_5_0-ibm-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_5_0-ibm-devel-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_5_0-ibm-fonts-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-alsa-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-jdbc-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_5_0-ibm-plugin-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-32bit-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-alsa-32bit-1.5.0_sr16.3-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_5_0-ibm-devel-32bit-1.5.0_sr16.3-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
