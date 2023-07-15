#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36216);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-1239", "CVE-2009-1905", "CVE-2009-1906");
  script_bugtraq_id(34650, 35171);

  script_name(english:"IBM DB2 9.1 < Fix Pack 7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple issues.");
  script_set_attribute(attribute:"description", value:
"According to its version, the IBM DB2 server running on the remote
host is prior to 9.1 Fix Pack 7. It is, therefore, affected by
multiple vulnerabilities :

  - In certain situations an INNER JOIN predicate is applied
    before the OUTER JOIN predicate, which could result in 
    disclosure of sensitive information. (JR31886)

  - It may be possible to connect to DB2 servers without
    valid passwords, provided LDAP-based authentication
    is used, and the remote LDAP server is configured to
    allow anonymous binds. (JR32272)

  - By connecting to a DB2 server using a third-party DRDA
    client that uses IPV6 address format of the correlation
    token, it may be possible to crash the remote DB2
    server. (IZ36683)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg21255607#7");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR31886");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR32272");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ36683");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 Version 9.1 Fix Pack 7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/22");

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

level = get_kb_item_or_exit("DB2/"+port+"/Level");
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

#Windows 32-bit
if (platform == 5)
{
  fixed_level = '9.1.700.855';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
else if (platform == 18)
{
  fixed_level = '9.1.0.7';
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
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" and is not affected.");
