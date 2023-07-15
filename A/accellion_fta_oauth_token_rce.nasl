#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85005);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-2857");
  script_xref(name:"EDB-ID", value:"37597");

  script_name(english:"Accellion Secure File Transfer Appliance 'oauth_token' Parameter Remote Command Execution");
  script_summary(english:"Attempts to execute a command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Accellion Secure File Transfer Appliance is affected by a
remote command execution vulnerability due to improper sanitization of
user-supplied in put to the 'oauth_token' parameter in the
get_oauth_customer_name() and verify_oauth_token() functions. The
parameter is passed to a system() command through the 'twsgetStatus'
handler. A remote, unauthenticated attacker can exploit this
vulnerability to execute arbitrary commands on the remote host.

Note that the twsPut, twssetStatus, twsGet, Find, Put, and mPut
handlers are also reportedly affected by this issue; however, Nessus
has not tested these additional handlers.");
  # https://blog.rapid7.com/2015/07/10/r7-2015-08-accellion-file-transfer-appliance-vulnerabilities-cve-2015-2856-cve-2015-2857/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f6a5d7f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Accellion Secure File Transfer Appliance version
FTA_9_11_210 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2857");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Accellion FTA getStatus verify_oauth_token Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:accellion:secure_file_transfer_appliance");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("accellion_file_transfer_appliance_detect.nbin");
  script_require_keys("installed_sw/Accellion Secure File Transfer Appliance");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Accellion Secure File Transfer Appliance";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(app_name:app, port:port);
install_url = build_url(port:port, qs:"/");

data = "transaction_id=1&oauth_token='%3becho '";
clear_cookiejar();
res = http_send_recv3(
  method : "POST",
  port   : port,
  data   : data,
  item   : "/tws/getStatus",
  add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);
if (!egrep(pattern:'"result_msg":"Success"', string:res[2]))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  cmd         : 'echo',
  line_limit  : 3,
  request     : make_list(http_last_sent_request()),
  output      : chomp(res[2])
);
