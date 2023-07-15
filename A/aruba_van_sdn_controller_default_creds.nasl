#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122755);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/27 13:17:50");

  script_xref(name:"EDB-ID", value:"44951");

  script_name(english:"Aruba VAN SDN default credentials");
  script_summary(english:"Detects default credentials");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is configured with
default credentials.");
  script_set_attribute(attribute:"description", value:
"The Aruba Virtual Application Networks (VAN) Software Defined
Networking (SDN) controller running on the remote host is
configured with default credentials. A default service token is
configured or the 'sdn' account is using a default password. An
unauthenticated, remote attacker can exploit this to gain privileged
or administrator access to the system.");
  script_set_attribute(attribute:"solution", value:
"Change the default credentials. Refer to chapter 7, section Security
procedure in the Aruba VAN SDN Controller Administrator Guide.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default credentials can be used to gain a root shell.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:arubanetworks:van_sdn_controller");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("aruba_van_sdn_controller_detect.nbin");
  script_require_keys("installed_sw/Aruba VAN SDN Controller");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Aruba VAN SDN Controller";

# Exit if app is not detected on the target
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8443, php:TRUE);

# Exit if app is not detected on the port
install = get_single_install(
  app_name : app,
  port     : port
);

vuln = FALSE;

#
# Check default service token
#
url = "/sdn/ui/app/rs/hpws/config";
res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : url,
  add_headers: make_array("X-Auth-Token", "AuroraSdnToken37"),
  exit_on_fail : TRUE
);

if ("200" >< res[0]) vuln = TRUE;
else
{

  #
  # Check default user/password
  #
  url = "/sdn/ui/app/login";
  res = http_send_recv3(
    method : "POST",
    port   : port,
    item   : url,
    data   : "username=sdn&password=skyline",
    exit_on_fail : TRUE
  );
  if ("303" >< res[0]) vuln = TRUE;
}

if(vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    generic     : TRUE,
    request     : make_list(http_last_sent_request()),
    output      : res[0] + res[1] + res[2]
  );
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));
}
