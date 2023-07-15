#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(159550);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/06");

  script_name(english: "Web Site Accepts Credit Card Data over cleartext HTTP");
  script_set_attribute(attribute:"synopsis", value:"Identifies web forms that accept credit card data and are not secured by SSL/TLS.");

  script_set_attribute(attribute:"description", value:
"The remote web server contains at least one HTML form field that has
an input of type 'cc-number' or similar.

While this does not represent a risk to this web server per se, it
does mean that the website may be accepting payment information.");
  # https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75653fc3");
  script_set_attribute(attribute:"solution", value:"Use TLS for this webserver.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score from an in depth analysis done by Tenable");

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

if ( get_port_transport(port) == ENCAPS_IP )
{
  var kb = get_kb_item_or_exit("www/" + port + "/AutoCompleteCCFields");

  var report = 'The following credit card related fields were observed: \n';
  foreach var line (split(kb, keep: 0))
    report += split_long_line(line: line) + '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}

# 2, "$1$ was not detected on the web server listening on port $2$." 
audit(AUDIT_WEB_APP_NOT_INST, "A web page accepting credit cards ", port);
