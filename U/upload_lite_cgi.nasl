#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(11359);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(7051);

  script_name(english:"Upload Lite upload.cgi Arbitrary File Upload");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that may allow arbitrary
uploads.");
  script_set_attribute(attribute:"description", value:
"The Upload Lite (upload.cgi) CGI script is installed.  This script has
a well-known security flaw that lets anyone upload arbitrary files on
the remote web server. 

Note that Nessus did not test whether uploads are possible, only that
the script exists.");
  script_set_attribute(attribute:"solution", value:
"Remove the affected script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "find_service1.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

found_files = "";
foreach d ( cgi_dirs() )
{
 loc = string(d, "/upload.cgi");
 r = http_send_recv3(method:"GET", item:loc, port:port);
 if (isnull(r)) exit(0);
 res = r[2];

 if(
  "<title>PerlScriptsJavascript.com " >< res &&
  "This script must be called" >< res
 ){
  found_files = string(found_files, "  ", loc, "\n");
  if (!thorough_tests) break;
 }
}

if (found_files != ""){
 report = string(
  "The Upload Lite CGI was found at the following locations :\n",
  "\n",
  "  ", found_files
 );
 security_hole(port:port, extra:report);
 exit(0);
}

