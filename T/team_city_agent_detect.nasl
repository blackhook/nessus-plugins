#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94675);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"JetBrains TeamCity Agent XML-RPC Port RCE");
  script_summary(english:"Checks for presence of TeamCity agent.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The JetBrains TeamCity agent running on the remote host is affected by
a remote command execution vulnerability due to the agent behaving as
a bidirectional agent even when the unidirectional protocol is
enabled. An unauthenticated, remote attacker can exploit this to
execute commands via the XML-RPC port, resulting in the disclosure of
sensitive information, a denial of service condition, or the execution
of arbitrary shell commands.");
  script_set_attribute(attribute:"see_also", value:"https://www.jetbrains.com/teamcity/");
  # https://confluence.jetbrains.com/display/TCD10/Setting+up+and+Running+Additional+Build+Agents
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?980a98d4");
  script_set_attribute(attribute:"solution", value:
"Use unidirectional agent communication and upgrade JetBrains TeamCity
agent to version 10.0 (42002) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:jetbrains:teamcity");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"RPC");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports(9090, "Services/www");
  script_dependencies("http_version.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("webapp_func.inc");

appname = "TeamCity Agent";
port = get_http_port(default:9090);

##
# This function is used to report one successful RPC if, for
# some odd reason, the second one fails.
#
# @param version the build reported by getVersion
# @return No return - this function exits
##
function report_one(version)
{
  register_install(
    vendor:"JetBrains",
    product:"TeamCity",
    app_name:appname,
    port:port,
    path:'/',
    version:version,
    cpe:"cpe:/a:jetbrains:teamcity");

  report = '\nNessus was able to issue a remote procedure call to the ' +
    '\nremote TeamCity agent. Nessus received the following response :' +
    '\n' +
    '\nbuildAgent.getVersion: Build ' + version + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}

banner = get_http_banner(port:port);
if (isnull(banner)) audit(AUDIT_NO_BANNER, port);

# The agent server is built upon Apache's XML-RPC server
if ("Apache XML-RPC" >!< banner) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Try to issue a TeamCity agent RPC command
getVersion = '<methodCall><methodName>buildAgent.getVersion</methodName></methodCall>';
resp = http_send_recv3(port:port, method:'POST', item:'/', data:getVersion, exit_on_fail:FALSE);
if (isnull(resp) || "200 OK" >!< resp[0]) audit(AUDIT_WEB_APP_NOT_INST, appname, port);

# Extract the response
item = eregmatch(pattern:"<methodResponse><params><param><value>(.*)</value></param></params></methodResponse>", string:resp[2]);
if (isnull(item)) audit(AUDIT_WEB_APP_NOT_INST, appname, port);
version = item[1];

# Now get the OS information
getOS = '<methodCall><methodName>buildAgent.getOperatingSystemName</methodName></methodCall>';
resp = http_send_recv3(port:port, method:'POST', item:'/', data:getOS, exit_on_fail:FALSE);
if (isnull(resp) || "200 OK" >!< resp[0]) report_one(version:version);

# Extract the response
item = eregmatch(pattern:"<methodResponse><params><param><value>(.*)</value></param></params></methodResponse>", string:resp[2]);
if (isnull(item)) report_one(version:version);
extra = make_array();
extra["osName"] = item[1];

register_install(
  vendor:"JetBrains",
  product:"TeamCity",
  app_name:appname,
  port:port,
  path:'/',
  extra:extra,
  version:version,
  cpe:"cpe:/a:jetbrains:teamcity");

report =
  '\nNessus was able to issue remote procedure calls to the remote ' +
  '\nTeamCity agent. Nessus received responses for two calls : ' +
  '\n' +
  '\nbuildAgent.getVersion : Build ' + version +
  '\nbuildAgent.getOperatingSystemName : ' + extra["osName"] + '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
