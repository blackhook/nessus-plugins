#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47831);
  script_version("1.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic XSS (comprehensive test)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings of malicious JavaScript.  By leveraging this
issue, an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site.  These XSS are likely to be 'non-persistent' or
'reflected'.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross_site_scripting#Non-persistent");
  # https://blog.jeremiahgrossman.com/2009/06/results-unicode-leftright-pointing.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9a0369");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application.  Contact the vendor
for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 80, 81, 83, 84, 85, 86, 87, 116, 442, 692, 712, 722, 725, 751, 801, 811, 928, 931);

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "cross_site_scripting.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
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

i = 0; 
flaws_and_patterns = make_array(
# "<script > alert(201); </script >",   "RE:<script *> *alert\(201\); *</script *>",
 '"><script > alert(201); </script >',   'RE:[^\\\\]"><script *> *alert\\(201\\); *</script *>',
##  "<IMG SRC=a onerror=alert(String.fromCharCode(88,83,83))>", ...,

# UTF-7 encoded
  "+ADw-script+AD4-alert(202)+ADw-/script+AD4-", "RE:<script>alert\(202\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.2.0.2.\).<./.s.c.r.i.p.t.>",
# UTF-16 encoded (works with IE)       
  "%FF%FE%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%32%30%33%29%3C%2F%73%63%72%69%70%74%3E", 
  "RE:<script>alert\(203\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.2.0.3.\).<./.s.c.r.i.p.t.>",

  '%22%3E%3Cimg%20src=1%20onerror=javascript:alert%28205%29%3E',
   'ST:"><img src=1 onerror=javascript:alert(505)>',
  '<<<<<<<<<<foo"bar\'204>>>>>',	'ST:<<foo"bar\'204>>'
);

# Interesting patterns:
# "><ScRiPt>alert(42)</ScRiPt>
# " onerror="alert(42)

if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
{
  flaws_and_patterns["< script > alert(204); </ script >"] = "RE:< *script *> *alert\(204\); *</ *script *>";
  # If the charset is not specified (and different from UTF-7), then this should work too
  flaws_and_patterns["+ADw-script+AD4-alert(205)+ADw-/script+AD4-"] = 
    "RE:\+ADw-script\+AD4-alert(205)\+ADw-/script\+AD4-|<script>alert\(205\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.2.0.5.\).<./.s.c.r.i.p.t.>";
  # Netscape 4 only - CVE-2002-0738
  flaws_and_patterns["<b foo=&{alert(206)};>"] =
    "ST:<b foo=&{alert(206)};>";
  flaws_and_patterns['>>>>>>>>>>foo"bar\'207<<<<<'] =
    'ST:>>foo"bar\'207<<';
}

if (thorough_tests)
{
  # Base64 encoding
  flaws_and_patterns["PHNjcmlwdD5hbGVydCg5OSk7PC9zY3JpcHQ+"] = 
    "ST:'<script>alert(99);</script>";
  # Broken Base64 encoding - may circumvent mod_security
  # http://blog.modsecurity.org/2010/04/impedance-mismatch-and-base64.html
  flaws_and_patterns["P.HNjcmlwdD5hbGVydCg5OCk7PC9zY3JpcHQ+"] = 
    "ST:'<script>alert(98);</script>";

  flaws_and_patterns["%u00ABscript%u00BBalert(209);%u00AB/script%u00BB"] = 
    "RE:<script *> *alert\(209\); *</script *>";
  flaws_and_patterns["&#x3008;script&#x3009;alert(210);&#x3008;/script&#x3009;"] =
    "RE:<script *> *alert(210); *</script *>";
  flaws_and_patterns["U%2bFF1CscriptU%2bFF1Ealert(211);/U%2bFF1CscriptU%2bFF1E"] =
    "RE:<script *> *alert(211); *</script *>";
  flaws_and_patterns["&#x2039;script&#x203A;alert(212);&#x2039;/script&#x203A;"] =
    "RE:<script *> *alert(212); *</script *>";
  flaws_and_patterns["&#x2329;script&#x232Aalert(213);&#x2329;/script&#x232A"] =
    "RE:<script *> *alert(213); *</script *>";
  flaws_and_patterns["&#x27E8;script&#x27E9;alert(214);&#x27E8;/script&#x27E9;"] =
    "RE:<script *> *alert(214); *</script *>";

  flaws_and_patterns["+ADwAcwBjAHIAaQBwAHQAPgBhAGwAZQByAHQAKAA0ADIAKQA7ADwALwBzAGMAcgBpAHAAdAA+-"] =
    "RE:<script>alert\(42\);</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.4.2.\).;.<./.s.c.r.i.p.t.>";
  flaws_and_patterns["%3Cscript%3Ealert(216)%3B%3C%2Fscript%3E"] = 
    "ST:<script>alert(216);</script>";
  # CVE-2002-0738
  flaws_and_patterns["><scr<script>ipt>alert(217)</scr</script>ipt>"] = 
    "ST:><script>alert(217)</script>";
  # CVE-2005-2276, CVE-2005-0563...
  flaws_and_patterns["j&#X61vascript:alert(218)"] = 
    'ST:javascript:alert(218)';
  # BID 10724
  flaws_and_patterns['<%00script>alert(219);</script%00>'] =
    'ST:script>alert(219);</script';
}

port = torture_cgi_init(vul:'X2');


if (get_kb_item(strcat("www/", port, "/generic_xss")))
  exit(0, 'The web server is vulnerable to generic cross-site scripting');
# if (stop_at_first_flaw == "port" && ! thorough_tests && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

if (report_paranoia < 2)
  ct = "text/(xml|html)";
else
  ct = NULL;
report = torture_cgis(port: port, vul: "X2", only_content: ct, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
