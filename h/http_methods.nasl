#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10498);
 script_version("1.50");
 script_cvs_date("Date: 2018/08/08 12:52:14");

 script_bugtraq_id(12141);
 script_xref(name:"OWASP", value:"OWASP-CM-008");
 
 script_name(english:"Web Server HTTP Dangerous Method Detection");
 script_summary(english:"Verifies the access rights to the web server (PUT, DELETE)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server allows the PUT and/or DELETE method.");
 script_set_attribute(attribute:"description", value:
"The PUT method allows an attacker to upload arbitrary web pages on 
the server. If the server is configured to support scripts like ASP,
JSP, or PHP it will allow the attacker to execute code with the
privileges of the web server.

The DELETE method allows an attacker to delete arbitrary content from
the web server.");
 script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7231#section-4.3.4");
 script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7231#section-4.3.5");
 script_set_attribute(attribute:"solution", value:
"Disable the PUT and/or DELETE method in the web server configuration.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft IIS WebDAV Write Access Code Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/30");
 script_set_attribute(attribute:"vuln_publication_date", value:"1994/01/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2018 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");

# the file data we'll upload
put_data = "Nessus was here.";

##
# Try to generate a filename that does't exist on the
# remote HTTP server. We'll try 20 times before giving up.
#
# @param port the port to send the HTTP request
# @return a filename or NULL
##
function generate_filename(port)
{
  var i = 0;
  var filename = NULL;

  for ( ; i < 20; i++)
  {
    filename = rand_str(length:12);

    # exit on fail here because if we hit some type of
    # critical failure while generating our test filename
    # then there is no reason to keep going
    var request_file = http_send_recv3(
      method:"GET",
      port:port,
      item:"/" + filename,
      exit_on_fail:TRUE);

    if (!empty_or_null(request_file) && "404" >< request_file[0])
    {
      return filename;
    }
  }

  return NULL;
}

##
# Tries to upload a file to the remote server using PUT. Tests
# if we were successful using GET.
#
# @param port the port the HTTP server is on
# @param filename the filename we are atempting to upload
# @return TRUE if the upload was successful and FALSE otherwise
##
function test_put(port, filename)
{
  # blindly send the PUT
  http_send_recv3(
    method:"PUT",
    port:port,
    item:"/" + filename,
    add_headers: make_array("Content-Type", "text/html"),
    data:put_data);

  # check if the file exists
  var request_file = http_send_recv3(
    method:"GET",
    port:port,
    item:"/" + filename);

  if (!empty_or_null(request_file) && "200" >< request_file[0] &&
    request_file[2] == put_data)
  {
    # set kb items we can use downstream
    set_kb_item(name:'www/put_upload', value:TRUE);
    set_kb_item(name:'www/' + port + '/put_upload', value:TRUE);
    return TRUE;
  }

  return FALSE;
}

# This plugin intinitally ignores the HTTP OPTIONS response.
# Just because PUT/DELETE are listed as Allowed doesn't mean
# that these methods will *actually* write files to disk.
# As such, relying on that output will only result in FP.
#
# This plugin also reflects the fact that if we fail PUT then
# we can't test DELETE.
#
# Finally, if PUT works but DELETE doesn't then we've left
# a file on the server... which should be ACT_DESTRUCTIVE
# but it appears that this script has always been ACT_ATTACK

port = get_http_port(default:80);

# generate a filename we can work with
name = generate_filename(port:port);
if (isnull(name))
{
  exit(1, "Failed to generate a random filename to test with.");
}

if (test_put(port:port, filename:name) == FALSE)
{
  audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
}

# We successfully created a file on the remote
# server. Let's try to delete it.
http_send_recv3(
  method:"DELETE",
  port:port,
  item:"/" + name);

final_request = http_send_recv3(
    method:"GET",
    port:port,
    item:"/" + name);

report = '\nThe remote web server on port ' + port + ' supports file upload using ' +
         '\nthe HTTP PUT method. Nessus was able to create a file: ' +
         '\n\n' + build_url(port:port, host:get_host_name(), qs:name);
if (!empty_or_null(final_request) && "404" >< final_request[0])
{
  report += '\n\nNessus was then able to delete the file using HTTP DELETE.\n';
  set_kb_item(name:'www/delete_upload', value:TRUE);
  set_kb_item(name:'www/' + port + '/delete_upload', value:TRUE);
}
else
{
  report += '\n\nUnfortunately, Nessus was unable to delete the file using' +
    'the HTTP DELETE method.\n';
}

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
