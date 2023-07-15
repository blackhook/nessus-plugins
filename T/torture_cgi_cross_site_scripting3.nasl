#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55903);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic XSS (extended patterns)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts one or more CGI scripts that fail to
adequately sanitize request strings with malicious JavaScript.  By
leveraging this issue, an attacker may be able to cause arbitrary HTML
and script code to be executed in a user's browser within the security
context of the affected site.  These XSS vulnerabilities are likely to
be 'non-persistent' or 'reflected'.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross_site_scripting#Non-persistent");
  # https://blog.jeremiahgrossman.com/2009/06/results-unicode-leftright-pointing.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9a0369");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application.  Contact the vendor
for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 80, 81, 83, 86, 116, 442, 692, 712, 722, 725, 751, 801, 811, 928, 931);

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation2.nasl", "torture_cgi_injectable_param.nasl");
  script_require_keys("Settings/enable_web_app_tests");
  script_require_ports("Services/www", 80);
  script_timeout(43200);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");

####

# Split complex regex
html_str = '"([^"\\\\]|\\\\.)*"|\'([^\'\\\\]|\\\\.)*\'';
html_attr = '[a-z0-9._-]+([ \t]*=[ \t]*(' + html_str + '|[^"\'> \t]+))?';
html_attr_list = '([ \t]+' + html_attr + ')*';
#

i = 0; 
flaws_and_patterns = make_array(
 # Try to inject the poison directly into an existing src field
 'javascript:alert(501)',	'RI:<[A-Z]+[^>]*[ \t]+(SRC|HREF)="javascript:alert\\(501\\)',

 # This works with all browsers on many HTML tags
 'onmouseover=alert(502)',	'RI:<[A-Z]+' + html_attr_list + '[ \t]+onmouseover=alert\\(502\\)',

  '503" onerror="alert(503);',	'RE:<[^>]*="[^"]*503" onerror="alert\\(503\\);.*".*>',
  '504 onerror="alert(504);',	'RE:<[^>]*=[^\'" ]*504 onerror="alert\\(504\\);.*".*>',
  '505\' onMouseOver=\'alert(505);',	'RE:<[^>]*=\'[^\']*505\' onMouseOver=\'alert\\(505\\);\'.*".*>',
  '506;alert(506)',	'RI:<[^>]* (onClick|onError|onMouseOver)="[^"]*506;alert\\(506\\);[^"]*".*>',

  '508 src=http://www.example.com/exploit508.js', 
    'RI:<[A-Z]+' + html_attr_list + '[ \t]+src=http://www\\.example\\.com/exploit508\\.js.*>',

  '509" src="http://www.example.com/exploit509.js', 
    'RI:<[A-Z]+' + html_attr_list + '[ \t]+src="http://www\\.example\\.com/exploit509\\.js.*>',
  '510\' src=\'http://www.example.com/exploit510.js', 
    'RI:<[A-Z]+' + html_attr_list + '[ \t]+src=\'http://www\\.example\\.com/exploit510\\.js.*>'
);

if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
{
 flaws_and_patterns[ '" onfocus="alert(502)' ] =
  'RE:<[^"]*("[^"]*")*[^"]*"" onfocus="alert\\(502\\)"';
}

port = torture_cgi_init(vul:'X3');

if (get_kb_item(strcat("www/", port, "/generic_xss")))
  exit(0, 'The web server is vulnerable to generic cross-site scripting');
# if (stop_at_first_flaw == "port" && ! thorough_tests && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

if (report_paranoia < 2)
  ct = "text/(xml|html)";
else
  ct = NULL;
report = torture_cgis(port: port, vul: "X3", only_content: ct, injectable_only: INJECTABLE_TEXT, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
