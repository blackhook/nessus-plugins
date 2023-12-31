#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80477);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/18");

  script_cve_id("CVE-2014-0963");
  script_bugtraq_id(67238);

  script_name(english:"Informix Server GSKit 7.x < 7.0.4.50 / 8.0.50.x < 8.0.50.20 SSL CPU Utilization DoS");
  script_summary(english:"Checks version of Informix Server and GSKit.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Informix server ships with a version of IBM's Global
Security kit (GSKit) library that is affected by a denial of service
vulnerability. A remote attacker can exploit this issue by sending a
specially crafted SSL request to cause the host to become
unresponsive.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21673008");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Informix server or apply the correct GSKit patch per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0963");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_gskit_installed.nasl", "ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM GSKit", "installed_sw/IBM Informix Dynamic Server");
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include("install_func.inc");
include('misc_func.inc');

ids_app = 'IBM Informix Dynamic Server';
ids_install = get_single_install(app_name:ids_app, exit_if_unknown_ver:TRUE);

ids_ver   = ids_install['version'];
ids_path  = ids_install['path'];

ids_fix   = NULL;
gsk_regex = NULL;
gsk_fix = NULL;

item = pregmatch(pattern: "[cC]([0-9]+)([^0-9]|$)",
                 string: ids_ver);
c_num = 0;
if (!isnull(item) && !isnull(item[1])) c_num = int(item[1]);

# 11.50 (currently no fix for 11.50 branch)
if (ids_ver =~ "^11\.50($|[^0-9])")
{
  ids_fix     = "None available. Upgrade GSKit.";
  gsk_regex = "^7\.";
  gsk_fix   = '7.0.4.50';
}
# 11.70 < 11.70.xC8
else if (ids_ver =~ "^11\.70($|[^0-9])" && c_num < 8)
{
  ids_fix     = "11.70.xC8";
  gsk_regex = "^8\.0\.50\.";
  gsk_fix   = "8.0.50.20";
}
# 12.10 < 12.10.xC4
else if (ids_ver =~ "^12\.10($|[^0-9])" && c_num < 4)
{
  ids_fix     = "12.10.xC4";
  gsk_regex = "^8\.0\.50\.";
  gsk_fix   = "8.0.50.20";
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, ids_app, ids_ver, ids_path);

# Check GSKit version if Informix is not patched
gsk_app = "IBM GSKit";

# We don't bother to exit if we can't detect any GSKit installations
gsk_installs = get_installs(app_name:gsk_app);
gsk_report   = NULL;
gsk_vuln     = 0;

foreach gsk_install (gsk_installs[1])
{
  gsk_ver  = gsk_install['version'];
  gsk_path = gsk_install['path'];

  if (gsk_ver =~ gsk_regex &&
      ver_compare(ver:gsk_ver, fix:gsk_fix, strict:FALSE) == -1)
  {
    gsk_report +=
      '\n  Path              : ' + gsk_path +
      '\n  Installed version : ' + gsk_ver  +
      '\n  Fixed version     : ' + gsk_fix  +
      '\n';

    gsk_vuln++;
  }
}
port = get_kb_item("SMB/transport");
if (!port) port = 445;

report =
  '\n' + 'The install of ' + ids_app + ' is vulnerable :' +
  '\n' +
  '\n' + '  Path              : ' + ids_path +
  '\n' + '  Installed version : ' + ids_ver  +
  '\n' + '  Fixed version     : ' + ids_fix  +
  '\n';

server_instances = get_kb_item("Host/" + ids_app + "/Server Instances");
if (!empty_or_null(server_instances))
{
  instance_list = split(server_instances, sep:' / ', keep:FALSE);
  report += '  Server instances  : ' + '\n      - ' + join(instance_list, sep:'\n      - ') + '\n';
}

if (!isnull(gsk_report))
{
  instance = " instance "; is_are   = " is ";

  if (gsk_vuln > 1) {instance = " instances "; is_are = " are ";}

  report +=
    '\nAlso, the following vulnerable'+instance+'of '+gsk_app+is_are+'installed on the'+
    '\nremote host :' +
    '\n' +
    gsk_report;
}

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
