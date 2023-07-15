#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51840);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-3731", "CVE-2011-0731", "CVE-2011-0757");
  script_bugtraq_id(46052, 46064, 46077);
  script_xref(name:"SECUNIA", value:"43059");
  script_xref(name:"SECUNIA", value:"43148");

  script_name(english:"IBM DB2 9.1 < Fix Pack 10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.1 running on
the remote host is prior to Fix Pack 10. It is, therefore, affected by
one or more of the following issues :

  - It is possible to execute non-DDL statements even after
    an user's DBADM authority has been revoked. (IC66811)

  - Multiple vulnerabilities in 'db2dasrrm' component could 
    allow arbitrary code execution. (IC71203)/(IC69986)");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-035/");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2011/Jan/582");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-036/");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2011/Jan/583");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg1IC66811");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg1IC69986");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg1IC71203");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21426108");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 Version 9.1 Fix Pack 10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
if (level !~ '^9\\.[01]\\.')  exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0 or 9.1 and thus is not affected.");

platform = get_kb_item_or_exit("DB2/"+port+"/Platform");
platform_name = get_kb_item("DB2/"+port+"/Platform_Name");
if (isnull(platform_name))
{
  platform_name = platform;
  report_phrase = "platform " + platform;
}
else
  report_phrase = platform_name;

vuln = FALSE;

# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.1.1000.504';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
# Others
else if (
  # Linux, 2.6 kernel 32/64-bit
  platform == 18 || 
  platform == 30 ||
  # AIX
  platform == 20
)
{
  fixed_level = '9.1.0.10';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
else
{
  info =
    'Nessus does not support version checks against ' + report_phrase + '.\n' +
    'To help us better identify vulnerable versions, please send the platform\n' +
    'number along with details about the platform, including the operating system\n' +
    'version, CPU architecture, and DB2 version to db2-platform-info@nessus.org.\n';
  exit(1, info);
}

if (vuln)
{
  report_db2(
      severity        : SECURITY_HOLE,
      port            : port,
      platform_name   : platform_name,
      installed_level : level,
      fixed_level     : fixed_level);
}
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
