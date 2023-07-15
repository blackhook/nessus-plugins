#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76112);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-6747", "CVE-2014-0963");
  script_bugtraq_id(65156, 67238);

  script_name(english:"IBM DB2 9.1 TLS/SSL Multiple DoS Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of IBM DB2 running on the
remote host is version 9.1. It is, therefore, affected by one or more
of the following vulnerabilities :

  - An unspecified error exists related to handling
    malformed certificate chains that could allow denial
    of service attacks. (CVE-2013-6747)

  - An unspecified error exists related to the TLS
    implementation that could allow certain error cases to
    cause 100% CPU utilization. (CVE-2014-0963)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671732");
  script_set_attribute(attribute:"solution", value:
"If the install is under an extended support contract, please contact
the vendor for a patch.

Alternatively, upgrade to one of the latest supported versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("db2_das_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/db2das", 523);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("db2_report_func.inc");

# There is no information regarding fix build numbers,
# so this plugin is strictly paranoid-only
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"db2das", default:523, exit_on_fail:TRUE);

level = get_kb_item_or_exit("DB2/" + port + "/Level");
if (level !~ "^9\.1\.") audit(AUDIT_NOT_LISTEN, "DB2 9.1", port);

# Go ahead and check platform to preserve unknown-platform
# reporting.
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
# Known platforms
if (
  (
    # Windows
    platform == 5  || platform == 23 ||
    # Linux, 2.6 kernel 32/64-bit
    platform == 18 || platform == 30 ||
    # AIX
    platform == 20
  )
  &&
  level =~ "^9\.1\."
)
{
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
      fixed_level     : 'See solution');
}
else audit(AUDIT_LISTEN_NOT_VULN, "DB2", port, level);
