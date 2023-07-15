#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33270);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"ASP.NET DEBUG Method Enabled");

  script_set_attribute(attribute:"synopsis", value:
"The DEBUG method is enabled on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to send debug statements to the remote ASP scripts.  An
attacker might use this to alter the runtime of the remote scripts.");
  # https://support.microsoft.com/en-us/help/815157/how-to-disable-debugging-for-asp-net-applications
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d999af3");
  script_set_attribute(attribute:"solution", value:
"Make sure that DEBUG statements are disabled or only usable by
authenticated users.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:asp.net");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

port = get_http_port(default:80, embedded: 0);

files = get_kb_list("www/" + port + "/content/extensions/aspx");
if ( isnull(files) ) exit(0, "No ASPX page was found on port "+port+".");
else files = make_list(files);

sig = get_http_banner(port:port);
r = http_send_recv3(port: port, item: files[0], method: "DEBUG", version: 11, 
  add_headers: make_array("Command", "stop-debug"), exit_on_fail: 1 );

if (r[0] =~ "^HTTP/1\.1 200 "  &&  'Content-Length: 2\r\n' >< r[1] &&
    r[2] == "OK")
	security_warning(port:port, extra:
  '\nThe request\n' 
+ http_last_sent_request() 
+ '\nProduces the following output :\n'
+ r[0] + r[1] + '\r\n' + r[2] );
