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
  script_id(66198);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2013-0169",
    "CVE-2013-0485",
    "CVE-2013-0809",
    "CVE-2013-1493"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SuSE 10 Security Update : java-1_6_0-ibm (ZYPP Patch Number 8544)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"IBM Java 6 was updated to SR13 FP1, fixing bugs and security issues.

More information can be found on :

http://www.ibm.com/developerworks/java/jdk/alerts/

and on :

http://www.ibm.com/developerworks/java/jdk/aix/j664/Java6_64.fixes.htm
l#SR13FP1

Security issues: - CVE-2013-0485- CVE-2013-0809

  - CVE-2013-0169. (CVE-2013-1493)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0169.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0485.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-0809.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2013-1493.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 8544.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

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
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-devel-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-fonts-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-jdbc-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"java-1_6_0-ibm-plugin-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"java-1_6_0-ibm-alsa-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-32bit-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-alsa-32bit-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-devel-32bit-1.6.0_sr13.1-0.14.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"java-1_6_0-ibm-plugin-32bit-1.6.0_sr13.1-0.14.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
