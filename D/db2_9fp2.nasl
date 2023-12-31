#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24699);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-1086",
    "CVE-2007-1087",
    "CVE-2007-1088",
    "CVE-2007-1228"
  );
  script_bugtraq_id(22677, 22729);

  script_name(english:"IBM DB2 < 9 Fix Pack 2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host allows unsafe access to several setuid-root binaries. A
local attacker can exploit this to crash the affected database server
or possibly even gain root-level access. 

In addition, the fenced userid may be able to access directories
without proper authorization.");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=480
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3852717");
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=481
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f1c047c");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2007/Feb/520");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2007/Feb/522");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255745");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21255747");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IY86711");
  script_set_attribute(attribute:"solution", value:
"Apply DB2 Version 9 Fix Pack 2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2007-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^9\\.[01]\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.0 or 9.1 and thus is not affected.");
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
  fixed_level = '9.1.100.129';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
# Linu, 2.6 Kernel 32/64-bit
else if (platform == 18 || platform == 30)
{
  fixed_level = '9.1.0.2';
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
exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
