#%NASL_MIN_LEVEL 70300
#
# This script was rewritten by Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10188);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Multiple Web Server printenv CGI Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that discloses information.");
  script_set_attribute(attribute:"description", value:
"The remote web server contains the 'test-cgi' test script, which is
included by default with some web servers. 

The printenv CGI returns its environment variables. This gives an 
attacker information like the installation directory, the server IP 
address (which is interesting if NAT is implemented), the server 
administrator's email address, the server and modules versions, the
shell environment variables...");
  script_set_attribute(attribute:"solution", value:
"Remove printenv from /cgi-bin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Manual analysis of the vulnerability");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');



port = get_http_port(default:80, embedded: 0);
if ( thorough_tests && get_kb_item('Settings/disable_cgi_scanning')) dirs = cgi_dirs();
else dirs = make_list('/cgi-bin');

foreach dir (dirs)
{
  u = strcat(dir, '/printenv');
  w = http_send_recv3(port: port, item: u, method: "GET", exit_on_fail: 1, follow_redirect: 2);
  if ( w[0] =~ "^HTTP/1\.[01] 200 " && "SCRIPT_NAME=" >< w[2] &&
       "GATEWAY_INTERFACE=" >< w[2] )
  {
    if (report_verbosity > 0)
    {
      e = strcat('\nThe CGI was found under :\n\n ', build_url(port: port, qs: u), '\n');
      if (report_verbosity > 1)
        e = strcat(e, '\nIts output was :\n\n', w[2], '\n');
      security_warning(port: port, extra: e);
    }
    else
      security_warning(port: port);
    exit(0);
  }
}

exit(0, 'printenv was not found on port '+port+'.');
