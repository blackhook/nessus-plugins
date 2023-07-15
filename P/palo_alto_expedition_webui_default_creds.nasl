#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135255);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/07");
  script_name(english:"Palo Alto Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for configuration migration software was detected using default credentials on the remote host.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Expedition account is using a default password. An unauthenticated, remote attacker can exploit this gain
privileged or administrator access to the system.");
  # https://www.paloaltonetworks.com/products/secure-the-network/next-generation-firewall/migration-tool
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?773598e1");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"score from a more in depth analysis done by Tenable");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paloaltonetworks:expedition_migration_tool");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_expedition_web_detect.nbin");
  script_require_keys("installed_sw/Palo Alto Expedition");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

get_kb_item_or_exit("installed_sw/Palo Alto Expedition");
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

include('http.inc');
include('vcf.inc');
include('url_func.inc');
include('install_func.inc');

app_name = "Palo Alto Expedition";
webapp = "Palo Alto Expedition Console";
cpe = 'cpe:/a:paloaltonetworks:expedition_migration_tool';
port = get_http_port();

version = UNKNOWN_VER;

username = 'admin';
password = 'paloalto';

data = "user=" + urlencode(str:username) + "&password=" + urlencode(str:password)
    + "&action=get&type=login_users";

res = http_send_recv3(
  method       : 'POST',
  port         : port,
  item         : '/bin/Auth.php',
  content_type : "application/x-www-form-urlencoded",
  data         : data,
  exit_on_fail : FALSE,
  follow_redirect : 1
);

if ('{"success":true}' >< res[2]){
  default_auth = TRUE;
  res = http_send_recv3(
    method       : 'GET',
    port         : port,
    item         : '/bin/MTSettings/settings.php?param=versions',
    exit_on_fail : FALSE,
    follow_redirect : 1
  );

  if (res[0] =~ '^HTTP/[0-9.]+ +200' && res[2] =~ '"success":true')
  {
    ver = pregmatch(string:res[2], pattern:'"Expedition":"([^"]+)"');
    if (!empty_or_null(ver) && !empty_or_null(ver[1]))
    {
      version = ver[1];
    }
  }
}
else {
  audit(AUDIT_HOST_NOT, "affected");
}

report = 'Installed version : ' + version;
report = 
  '\n' + "Nessus was able to log into the remote web interface" +
  '\n' + "using the following default credentials : admin/paloalto";

security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
