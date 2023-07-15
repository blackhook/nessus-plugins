#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110768);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Kubernetes unprivileged API access");

  script_set_attribute(attribute:"synopsis", value:
"Kubernetes allows unauthenticated command execution via API access if not configured properly.");
  script_set_attribute(attribute:"description", value:
"A remote, unauthenticated attacker is able to leverage API calls 
to execute commands and scripts or gain shell access via port 10250 (https)");
  # https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-authentication-authorization/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8483f69d");
  script_set_attribute(attribute:"solution", value:
"Only allow localhost connections, set up firewall and authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"NVD has no score for this CVE. Tenable research analyzed the issue and assigned one.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports(10250);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("ssl_funcs.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (!thorough_tests) audit(AUDIT_THOROUGH);
if (islocalhost()) exit(0, "This plugin does not run against the localhost.");

transport = ssl_transport(ssl:TRUE, verify:FALSE);
port = 10250;
if(!get_port_state(port)) audit(AUDIT_PORT_CLOSED,port);
page = '/runningpods/';
res = http_send_recv3(method:'GET', item:page, transport:transport, port:port, exit_on_fail:TRUE);

if ('200' >!< res[0] || 'PodList' >!< res[2]) audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);

request = 'https://' + get_host_name() + ':' + port + page;
security_report_v4(severity:SECURITY_HOLE, port:port, generic:TRUE, request:make_list(request), output:res[2]);
