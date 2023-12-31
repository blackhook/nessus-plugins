#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39007);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2009-1905",
    "CVE-2009-1906",
    "CVE-2009-3471",
    "CVE-2009-3472"
  );
  script_bugtraq_id(35171, 36540);
  script_xref(name:"SECUNIA", value:"36890");

  script_name(english:"IBM DB2 < 9.5 Fix Pack 4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The IBM DB2 database server running on the remote host is 
prior to 9.5 Fix Pack 4. It is, therefore, affected by  multiple
issues :

  - It may be possible to connect to DB2 servers without
    valid passwords, provided LDAP-based authentication
    is used and the remote LDAP server is configured to 
    allow anonymous binds. (JR32268)

  - It may be possible to trigger a denial of service
    condition by sending malicious 'connect' data stream.
    (IZ37697)

  - By connecting to a DB2 server using a third-party DRDA
    client that uses IPV6 address format of the correlation
    token, it may be possible to crash the remote DB2
    server. (IZ38874)

  - MODIFIED SQL DATA table function is not dropped even if
    the maintainer does not have privileges to maintain the
    objects. (IZ46774)

  - The 'DASAUTO' command can be run by a non-privileged
    user. (IZ40352)

  - It may be possible for an unauthorized user to insert,
    update, or delete rows in a table. (IZ50079)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21293566#4");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1JR32268");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ37697");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IZ38874");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21403619");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21386689");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.5 Fix Pack 4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/03");

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
# Windows 32-bit
if (platform == 5)
{
  fixed_level = '9.5.400.576';
  if (ver_compare(ver:level, fix:fixed_level) == -1)
    vuln = TRUE;
}
# Linux, 2.6 Kernel 32-bit
else if (platform == 18)
{
  fixed_level = '9.5.0.4';
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
else exit(0, "IBM DB2 "+level+" on " + report_phrase + " is listening on port "+port+" an is not affected.");
