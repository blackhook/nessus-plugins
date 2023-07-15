#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51972);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic XSS (Parameters Names)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize parameters name of malicious JavaScript.  By leveraging this
issue, an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross_site_scripting");
  script_set_attribute(attribute:"see_also", value:"http://capec.mitre.org/data/definitions/86.html");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 80, 81, 83, 116, 442, 712, 722, 725, 751, 801, 811, 928, 931);

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
  script_require_keys("Settings/enable_web_app_tests");
  script_require_ports("Services/www", 80);
  script_timeout(43200);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");
include("url_func.inc");

####

i = 0;
flaws_and_patterns = make_array(
# "<script>alert(301);</script>",   "ST:<script>alert(301);</script>",
  '<script>alert(302);</script>',   'RE:^([^"]|"([^"\\\\]|\\\\[\\\\"])*")*<script>alert\\(302\\);</script>',
  '"><script>alert(303);</script>', 'RE:[^\\\\]"><script>alert\\(303\\);</script>',

 # This works with IE6, not Firefox
 '<IMG SRC%3D"javascript:alert(304);">', 'ST:<IMG SRC="javascript:alert(304);">',
 # Try to inject the poison directly into an existing src field
 'javascript:alert(305)',	'RI:<[A-Z]+[^>]*[ \t]+(SRC|HREF)="javascript:alert\\(305\\)',

 # This works with all browsers on many HTML tags
 'onmouseover%3Dalert(306)', 'RE:<[a-zA-Z]+[^>]* onmouseover=alert\\(306\\)',

 "<BODY ONLOAD%3Dalert(307)>",	 "ST:<BODY ONLOAD=alert(307)>",
  "<script > alert(308); </script >",   "RE:<script *> *alert\(308\); *</script *>",
  '%00"><script>alert(309)</script>', 'ST:"><script>alert(309)</script>"',
 '<script\n>alert(310);</script\n>', 'ST:<script\n>alert(310);</script\n>',

  "<script > alert(311); </script >",   "RE:<script *> *alert\(311\); *</script *>",
##  "<IMG SRC=a onerror=alert(String.fromCharCode(88,83,83))>", ...,
  
# UTF-7 encoded
  "+ADw-script+AD4-alert(312)+ADw-/script+AD4-", "RE:<script>alert\(312\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.3.1.2.\).<./.s.c.r.i.p.t.>",
# UTF-16 encoded (works with IE)
  "%FF%FE%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%33%31%33%29%3C%2F%73%63%72%69%70%74%3E",
  "RE:<script>alert\(313\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.3.1.3.\).<./.s.c.r.i.p.t.>",
  '<<<<<<<<<<foo"bar\'314>>>>>',	'ST:<<foo"bar\'314>>'
);

port = torture_cgi_init(vul:'XN');

if (thorough_tests)
 e = make_list("pl", "php", "php3", "php4", "php5", "cgi", "asp", "aspx");
else
 e = NULL;

rep = run_injection_param_names(vul: "XN", ext_l: e);
if (rep) security_warning(port: port, extra: rep);
