#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103378);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/18");

  script_cve_id("CVE-2017-1508");

  script_name(english:"IBM Informix Dynamic Server 12.10.FC1 < 12.10.FC9W1 IBM Unspecified Local Privilege Escalation");
  script_summary(english:"Checks version of Informix Server.");

  script_set_attribute(attribute:"synopsis", value:
"A database server installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Informix Dynamic Server installed on the remote
host is 12.10.FC1 or later but prior to 12.10.FC9W1. It is, therefore,
affected by an unspecified flaw which may allow a local attacker to
gain elevated privileges. No further details have been provided.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22006872");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Informix Dynamic Server version 12.10.FC9W1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1508");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/21");

  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_informix_server_installed.nasl");
  script_require_keys("installed_sw/IBM Informix Dynamic Server");
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

item = pregmatch(pattern: "[fF][cC]([0-9]+)(?:[wW]([0-9]+))?(?:[^0-9]|$)", string: ids_ver);
if(isnull(item) || isnull(item[1])) audit(AUDIT_INST_PATH_NOT_VULN, ids_app, ids_ver, ids_path);

w_num = 0;
c_num = int(item[1]);
if (!isnull(item) && !isnull(item[2])) w_num = int(item[2]);

# 12.10.FC1 to 12.10.FC9 < 12.10.FC9W1
if (ids_ver =~ "^12\.10\.[fF][cC][1-9]($|[^0-9])" && (c_num < 9 || ( c_num == 9 && w_num < 1 )))
  ids_fix = "12.10.FC9W1";
else
  audit(AUDIT_INST_PATH_NOT_VULN, ids_app, ids_ver, ids_path);

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

security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
