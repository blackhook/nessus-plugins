#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159549);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/06");

  script_name(english: "Web Site Accepts Credit Card Data");
  script_set_attribute(attribute:"synopsis", value:"Identifies forms that accept credit card data.");

  script_set_attribute(attribute:"description", value:
"The remote web server contains at least one HTML form field that has
an input of type 'cc-number' or similar.

While this does not represent a risk to this web server per se, it
does mean that the website may be accepting payment information.");
  # https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75653fc3");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/06");

  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO); 
  script_family(english: "Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www",80);
  exit(0);
}

include("compat_shared.inc");
include("http.inc");

var port = get_http_port(default:80);

var kb = get_kb_item_or_exit("www/" + port + "/AutoCompleteCCFields");

var report = 'The following credit card related fields were observed: \n';
foreach var line (split(kb, keep: 0))
  report += split_long_line(line: line) + '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
