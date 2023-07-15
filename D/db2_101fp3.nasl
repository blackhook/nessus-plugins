#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(70455);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-3475", "CVE-2013-4032", "CVE-2013-4033");
  script_bugtraq_id(60255, 62018, 62747);

  script_name(english:"IBM DB2 10.1 < Fix Pack 3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 10.1 running on
the remote host is affected by the following vulnerabilities :

  - A stack-based buffer overflow error exists related to
    input validation in the Audit facility and could lead
    to privilege escalation and denial of service attacks.
    Note this issue does not affected installs on the
    Windows operating system. (CVE-2013-3475 / IC92498)

  - When a multi-node configuration is used, an error exists
    in the Fast Communications Manager (FCM) that could
    allow denial of service attacks. (CVE-2013-4032 /
    IC94434)

  - An unspecified error exists that could allow an attacker
    to gain SELECT, INSERT, UPDATE, or DELETE permissions to
    database tables. Note that successful exploitation
    requires the rights EXPLAIN, SQLADM, or DBADM.
    (CVE-2013-4033 / IC94757)");
  # https://www.ibm.com/blogs/psirt/security-bulletin-ibm-smart-analytics-system-5600-v3-is-affected-by-a-vulnerability-in-the-ibm-db2-fast-communications-manager-cve-2013-4032/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c3d99f6");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21610582");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21639355");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21650231");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21646809");
  script_set_attribute(attribute:"solution", value:
"Apply IBM DB2 version 10.1 Fix Pack 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ '^10\\.1\\.')  exit(0, "The version of IBM DB2 listening on port "+port+" is not 10.1.");

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
  fixed_level = '10.1.300.533';
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
  fixed_level = '10.1.0.3';
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

if (report)
{
  report_db2(
      severity        : SECURITY_HOLE,
      port            : port,
      platform_name   : platform_name,
      installed_level : level,
      fixed_level     : fixed_level);
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
