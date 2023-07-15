#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117484);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-11218", "CVE-2018-12326");

  script_name(english:"Pivotal Software Redis LUA < 3.2.12 / 4.0.x < 4.0.10 / 5.0 < 5.0rc2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"Redis requires a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Redis installed on the remote host is affected by
multiple vulnerabilities and therefore requires a security update.");
  script_set_attribute(attribute:"see_also", value:"http://antirez.com/news/119");
  script_set_attribute(attribute:"solution", value:
"Update to Redis 3.2.12, 4.0.10 or 5.0-rc2 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11218");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:redis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redis_detect.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/redis_server", 6379);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "Redis Server";
port = get_service(svc:"redis_server", default:6379, exit_on_fail:TRUE);
version = get_kb_item_or_exit("redis/" + port + "/Version");

fix = NULL;
if (version =~ "^[1-3]\.") fix = "3.2.12";
else if (version =~ "^4\.0") fix = "4.0.10";
else if (version =~ "^4\.9") fix = "4.9.102";

if (!isnull(fix) && ver_compare(ver:version, fix:fix) == -1)
{
  report =
    '\n  Port              : ' + port +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);
}
