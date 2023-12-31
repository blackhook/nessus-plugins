#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43172);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2009-4325",
    "CVE-2009-4326",
    "CVE-2009-4327",
    "CVE-2009-4328",
    "CVE-2009-4329",
    "CVE-2009-4330",
    "CVE-2009-4331",
    "CVE-2009-4332",
    "CVE-2009-4333",
    "CVE-2009-4334",
    "CVE-2009-4335",
    "CVE-2009-4438",
    "CVE-2009-4439"
  );
  script_bugtraq_id(37332);
  script_xref(name:"SECUNIA", value:"37759");

  script_name(english:"IBM DB2 9.5 < Fix Pack 5 Multiple Unspecified Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM DB2 database server installed on the remote host is 
prior to 9.5 Fix Pack 5. It is, therefore, affected by multiple
unspecified vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21293566");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21412902");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.5 Fix Pack 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 200, 264, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

port = get_service(svc:'db2das', default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^9\\.5\\.') exit(0, "The version of IBM DB2 listening on port "+port+" is not 9.5 and thus is not affected.");

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
# Windows, x86
if (platform == 5)
{
  fixed_level = '9.5.500.784';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
# Linux, x86 2.6 kernel
else if (platform == 18)
{
  fixed_level = '9.5.0.5';
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
      severity        : SECURITY_WARNING,
      port            : port,
      platform_name   : platform_name,
      installed_level : level,
      fixed_level     : fixed_level);
}
exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
