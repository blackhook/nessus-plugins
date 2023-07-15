#%NASL_MIN_LEVEL 70300
#
# This script was written by Matt Moore <matt.moore@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10572);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"CERT-CC", value:"CA-2000-02");

  script_name(english:"Microsoft IIS 5.0 Form_JScript.asp XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting an ASP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The script /iissamples/sdk/asp/interaction/Form_JScript.asp (of
Form_VBScript.asp) allows you to insert information into a form field
and once submitted re-displays the page, printing the text you
entered. This .asp doesn't perform any input validation. An attacker
can exploit this flaw to execute arbitrary script code in the browser
of an unsuspecting victim.");
  script_set_attribute(attribute:"solution", value:
"Remove the sample scripts from the server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2000-2022 Matt Moore");

  script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("Settings/ParanoidReport", "www/ASP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded:TRUE);
if ( ! can_host_asp(port:port) ) exit(0);


res = is_cgi_installed_ka(item:"/iissamples/sdk/asp/interaction/Form_JScript.asp", port:port);
if( res )
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}


