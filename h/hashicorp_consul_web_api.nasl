#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111351);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/02");

  script_name(english:"Hashicorp Consul Web UI and API access");
  script_summary(english:"Hashicorp Consul Web UI and API accessible without Authentication.");

  script_set_attribute(attribute:"synopsis", value:
"Hashicorp Consul Web UI and API is accessible remotely if not configured properly.");
  script_set_attribute(attribute:"description", value:
"A remote, unauthenticated attacker may able to access Consul Web UI and API  
to gather data, register services and gain remote access.");

  script_set_attribute(attribute:"see_also", value:"https://www.consul.io/docs/internals/security.html");
  script_set_attribute(attribute:"see_also", value:"https://www.consul.io/api/acl.html");
  script_set_attribute(attribute:"solution", value:
"Only allow localhost connections, set up firewall and ACLs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"NVD has no score for this CVE. Tenable research analyzed the issue and assigned one.");



  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hashicorp:consul");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8500);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("ssl_funcs.inc");
include("json.inc");

if (islocalhost()) exit(0, "This plugin does not run against the localhost.");

function json_check(res)
{
  if(empty_or_null(res) || res[0] !~ "200") audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
  var json = json_read(res[2]);
  if(typeof(json[0]) != "array") exit(1,"Error parsing JSON response from the server.");
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8500);
port = branch(ports);
if ((empty_or_null(port)) || (!get_port_state(port))) audit(AUDIT_NOT_LISTEN,'HTTP(S)', port);

report = '\n' + crap(data:'*', length:70) + '\n'; 
server = get_host_name() + ':' + port;

# Check the server is correct
res = http_send_recv3(
  method:"GET",
  port:port,
  item:'/',
  follow_redirect:3,
  exit_on_fail:TRUE);
if ((res[0] !~ "200") || ("www.consul.io" >!< res[2])) audit(AUDIT_WRONG_WEB_SERVER, port, 'Not Consul Web server.');

# Check the JSON response containing expected fields
res = http_send_recv3(
  method:"GET",
  port:port,
  item:'/v1/catalog/nodes',
  add_headers:make_array("Accept","application/json,application/javascript"),
  exit_on_fail:TRUE);
json_check(res:res);
if (("Address" >!< res[2]) || ("Node" >!< res[2])) audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

# Want to get the max possible JSON as the vulnerable agents may be listed there.
report += '\nThe following JSON formatted data was gathered from Consul Web API:\n' + res[2];
report += '\n' + crap(data:'*', length:70) + '\n'; 

# Check response is JSON and starts with an '{'.
# at this stage, if the response is available, the attacker may be able to register a new service.
res = http_send_recv3(
  method:"GET",
  port:port,
  item:'/v1/agent/checks',
  add_headers:make_array("Accept","application/json,application/javascript"),
  exit_on_fail : TRUE);
json_check(res:res);
if (res[2] !~ "^{") audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
if (len(res[2]) > 3)
{
  report += '\nChecks registered with the local agent:\n' + res[2];
  report += '\n' + crap(data:'*', length:70) + '\n';
}

# Quick ACL list dump, if any.
res = http_send_recv3(
  method:"GET",
  port:port, 
  item:'/v1/acl/list',
  exit_on_fail:TRUE);
 if(!empty_or_null(res))
 {
  report += '\nACL policy:\n' + res[2];
  report += '\n\n' + crap(data:'*', length:70) + '\n';
 }

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
