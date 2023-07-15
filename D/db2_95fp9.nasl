#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58293);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2012-0709",
    "CVE-2012-0710",
    "CVE-2012-0711",
    "CVE-2012-0712",
    "CVE-2012-1796",
    "CVE-2012-1797"
  );
  script_bugtraq_id(52326);

  script_name(english:"DB2 9.5 < Fix Pack 9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 9.5 running on
the remote host is prior to Fix Pack 9. It is, therefore, affected by
the following vulnerabilities :

  - Incorrect, world-writable file permissions are in place
    for the file 'NODES.REG'. (IC79518)

  - An unspecified error can allow attacks to cause a
    denial of service via unspecified vectors. (IC76899)

  - A local user can exploit a vulnerability in the bundled
    IBM Tivoli Monitoring Agent (ITMA) to escalate their
    privileges. (IC79970)

  - An unspecified error in the DB2 Administration Server
    (DAS) can allow remote privilege escalation or denial
    of service via unspecified vectors. Note that this
    issue does not affect Windows hosts. (IC80728)

  - An authorized user with 'CONNECT' privileges from
    'PUBLIC' can cause a denial of service via unspecified
    methods related to DB2's XML feature. (IC81379)

  - An authorized user with 'CONNECT' and 'CREATEIN'
    privileges on a database can perform unauthorized
    reads on tables. (IC81387)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24032087");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21293566#9");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21586193");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC79970");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81379");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IC81387");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 9.5 Fix Pack 9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/"+port+"/Level");
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
# Windows 32-bit/64-bit
if (platform == 5 || platform == 23)
{
  fixed_level = '9.5.900.456';
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
  fixed_level = '9.5.0.9';
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
