#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10698);
  script_version("1.46");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(2513);

  script_name(english:"WebLogic Server Encoded Request Directory Listing");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WebLogic Server running on the remote host is affected
by an information disclosure vulnerability. An unauthenticated, remote
attacker can exploit this, via a crafted request, to display a listing
of an arbitrary directory, which may contain sensitive files.

Note that this installation may also be affected by a flaw that allows
an attacker to view the source code of JSP files; however, Nessus has
not tested for this issue.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Mar/402");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for an appropriate patch");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:weblogic_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("weblogic_detect.nasl");
  script_require_keys("www/weblogic");
  script_require_ports("Services/www", 80, 7001);

  exit(0);
}
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');

get_kb_item_or_exit('www/weblogic');
port = get_http_port(default:7001);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

reqs = make_list('/%00', '/%2e', '/%2f', '/%5c');

# Check for dir listing on index
dir_lists = get_kb_list('www/'+port+'/content/directory_index');

# Exit if we've already flagged the directory.
foreach dir_list (dir_lists)
{
  if ('/' >< dir_list)
    exit(0, "A directory listing has already been identified on the web server at "+build_url(qs:dir_list, port:port));
}

foreach req (reqs)
{
  res = http_send_recv3(
    method : 'GET',
    port   : port,
    item   : req,
    exit_on_fail : TRUE
  );
  res = tolower(res[2]);
  if (
    ('directory listing of' >< res) ||
    ('index of' >< res)
  )
  {
    output = strstr(res, 'index of');
    if (empty_or_null(output))
      output = strstr(res, 'directory listing of');
    if (empty_or_null(output))
      output = res[2];

    security_report_v4(
      port         : port,
      generic      : TRUE,
      severity     : SECURITY_WARNING,
      request      : make_list(build_url(qs:req, port:port)),
      output       : output
    );
    exit(0);
  }
}
audit(AUDIT_LISTEN_NOT_VULN, 'WebLogic', port);
