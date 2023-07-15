#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if(description)
{
  script_id(158094);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_name(english:"Apache Solr Unauthenticated Access Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses configuration information.");
  script_set_attribute(attribute:"description", value:
"A remote unauthenticated attacker can obtain an overview of the remote Apache Solr web server's configuration by
requesting the URL '/solr'.  This overview includes the configuration of the system and available data sources.
It may also include the contents of any cores configured in the node.");
# https://solr.apache.org/guide/8_11/authentication-and-authorization-plugins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be0fc91e");
  script_set_attribute(attribute:"solution", value:
"Update Apache Solr's configuration to require authentication.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute: "cvss_score_source", value: "manual");
  script_set_attribute(attribute: "cvss_score_rationale", value:"Information Disclosure");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 Tenable Network Security, Inc.");

  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr");
  script_require_ports("Services/www", 8983);
  exit(0);
}

include('debug.inc');
include('http.inc');
include('install_func.inc');
include('json.inc');

var appname = 'Apache Solr';

get_install_count(app_name:appname, exit_if_zero:TRUE);
var port = get_http_port(default:8983);
var install = get_single_install(app_name:appname, port:port);

var test_item = install['path'] + '/admin/cores?action=STATUS&indexInfo=false&wt=json';

var res = http_send_recv3(method:'GET', port:port, item:test_item, exit_on_fail:TRUE);

dbg::log(msg:'Request:\n' + http_last_sent_request() + '\n');
dbg::log(msg:'Response:\nSTATUS:\n' + res[0] + '\nHEADERS:\n' + res[1] + '\nBODY:\n' + res[2] + '\n');

if ('200' >< res[0])
{
  var json = json_read(res[2]);
  if (typeof(json) != 'array')
     audit(AUDIT_LISTEN_NOT_VULN, appname, port);

  var core_names = '';
  foreach var status (json[0]['status'])
  {
    if (!empty_or_null(status['name']))
      core_names += status['name'] + ', ';
  }

  var report = 'Nessus has determined that the Apache Solr instance at ' + build_url(port:port, qs:install['path']) + '\n'
             + 'does not require authentication to access the node management pages. Nessus requested\n'
             + build_url(port:port, qs:test_item) + ' and did\nnot receive a request for authorization.\n';
  if (!empty_or_null(core_names))
    report += strcat('\nCores found: ', core_names, '\n');

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}

var install_url = build_url(port:port, qs:install['path']);
audit(AUDIT_LISTEN_NOT_VULN, appname, install_url);
