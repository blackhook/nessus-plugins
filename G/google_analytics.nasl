#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if(description)
{
  script_id(40668);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Google Analytics on An Internal Web Server Detection");

  script_set_attribute(attribute:"synopsis", value:
"Google Analytics is installed.");
  script_set_attribute(attribute:"description", value:
"A link to urchin.js from Google Analytics has been found on this
internal web server.");
  script_set_attribute(attribute:"see_also", value:"https://marketingplatform.google.com/about/analytics/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of Google Analytics is compliant with your
organization's security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:analytics");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("network_func.inc");

if (! is_private_addr()) exit(0, "IP address is public.");

port = get_http_port(default: 80, embedded: 0);

l = get_kb_list(strcat("www/", port, "/external_javascript"));
if (isnull(l)) exit(0);
l = make_list(l);

report = "";
foreach k (l)
{
  v = eregmatch(string: k, pattern: "^page: (.+) link: (.+)$");
  if (! isnull(v))
  {
    if (v[2] == "http://www.google-analytics.com/urchin.js")
    report = strcat('  - ', v[1],'\n');
    if (!thorough_tests) break;
  }
}

if (report)
{
  if (max_index(split(report)) > 1) s = "these pages";
  else s = "this page";

  security_note(port: port, extra: strcat('\nurchin.js was seen in ", s, " :\n\n', report));
}
