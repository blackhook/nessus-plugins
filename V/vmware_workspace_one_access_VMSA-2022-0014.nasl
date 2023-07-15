#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(161331);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-22972");
  script_xref(name:"VMSA", value:"2022-0014");
  script_xref(name:"IAVA", value:"2022-A-0215");
  script_xref(name:"CEA-ID", value:"CEA-2022-0020");

  script_name(english:"VMware Workspace One Access / VMware Identity Manager Authentication Bypass (Direct Check) (CVE-2022-22972)");

  script_set_attribute(attribute:"synopsis", value:
"An identity store broker application running on the remote host is affected by an Authentication Bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The VMware Workspace One Access (formerly VMware Identity Manager) application running on the remote host is affected
by an authentication bypass vulnerability affecting local domain users.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0014.html");
  script_set_attribute(attribute:"see_also", value:"https://core.vmware.com/vmsa-2022-0014-questions-answers-faq");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/88438");
  # https://www.horizon3.ai/vmware-authentication-bypass-vulnerability-cve-2022-22972-technical-deep-dive/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77eaa74d");
  script_set_attribute(attribute:"solution", value:
"Apply the HW-156875 hotfix to VMware Workspace One Access / VMware Identity Manager as per the VMSA-2022-0014 advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workspace_one_access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:identity_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workspace_one_access_web_detect.nbin");
  script_require_keys("installed_sw/VMware Workspace ONE Access");

  exit(0);
}

include('http.inc');
include('debug.inc');
include('install_func.inc');

var app = 'VMware Workspace ONE Access';

get_install_count(app_name:app, exit_if_zero:TRUE);

# our web detection only fires on port 8443, while the exploit only works on port 443
# so we need to run this and have the plugin fire on 443
var port = get_http_port(default:443);

# http_send_recv3() and http_send_recv_req() overwrites any Host headers with the target host so we can't use
# those here, have to build and send our request manually
var bad_req =
  'GET /SAAS/auth/login/embeddedauthbroker/callback HTTP/1.1\r\n' +
  'Host: nessus\r\n' +
  'Connection: close\r\n' +
  '\r\n';

var res = _http_send_recv_once(port:port, buf:bad_req, exit_on_fail:TRUE);

dbg::detailed_log(
  lvl:2, 
  msg:'Request / Response details from _http_send_recv_once() for port ' + port + ':\n' +
      'Request (' + port + '):\n' + http_last_sent_request() +
      'Response Code (' + port + '): ' + res[0] +
      'Response Body (' + port + '):\n' + res[2] + '\n\n'
);

# 444 response is patched, 200 is vuln
# so we audit out on anything other than 200
if ('200' >!< res[0])
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

# vuln
security_report_v4(port:port, severity:SECURITY_HOLE, request:[http_last_sent_request()], output:res[2], generic:TRUE);