#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46193);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic XSS (HTTP Headers)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize HTTP headers of malicious JavaScript.  By leveraging this
issue, an attacker may be able to cause arbitrary HTML and script code
to be executed in a user's browser within the security context of the
affected site.  Note that injecting HTTP headers needs an additional
flaw or a special vector (like a Flash applet). 

Note that these cross-site scripting vulnerabilities are likely to be
'non persistent', also called 'reflected'.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross_site_scripting#Non-persistent");
  script_set_attribute(attribute:"see_also", value:"http://capec.mitre.org/data/definitions/86.html");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 80, 81, 83, 116, 442, 712, 722, 725, 751, 801, 811, 928, 931);

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

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

i = 0;
headers[i++] = "Referer";
headers[i++] = "Cookie";
headers[i++] = "User-Agent";
headers[i++] = "Pragma";
headers[i++] = "Accept";
headers[i++] = "X-Forwarded-For";
headers[i++] = "Accept-Language";
headers[i++] = "Accept-Charset";
# These headers will seriously disrupt the protocol
headers[i++] = "Expect";
headers[i++] = "Connection";
headers[i++] = "Host";
headers[i++] = "Content-Type";
headers[i++] = "Content-Length";
# To be completed...

####

single_quote = raw_string(0x27);
double_quote = raw_string(0x22);
postheaders = make_array("Content-Type", "application/x-www-form-urlencoded");

i = 0;
flaws_and_patterns = make_array(
 "<script>alert(401);</script>",   "ST:<script>alert(401);</script>",
 '<IMG SRC="javascript:alert(402);">', 'RE:<IMG( |%20)SRC="javascript:alert\\(402\\);">',
 "<BODY ONLOAD=alert(403)>",	 "ST:<BODY ONLOAD=alert(403)>",
  "<script > alert(404); </script >",   "RE:<script *> *alert\(404\); *</script *>",
##  "<IMG SRC=a onerror=alert(String.fromCharCode(88,83,83))>", ...,
  
# UTF-7 encoded
  "+ADw-script+AD4-alert(405)+ADw-/script+AD4-", "RE:<script>alert\(405\)</script>|.<.s.c.r.i.p.t.>.a.l.e.r.t.\(.4.0.5.\).<./.s.c.r.i.p.t.>",
  '<<<<<<<<<<foo"bar\'406>>>>>',	'ST:<<foo"bar\'406>>',
  '>>>>>>>>>>foo"bar\'407<<<<<',	'ST:>>foo"bar\'407<<'
);

global_var headers;

function test_local(meth, url, postdata, cgi, vul)
{
  local_var	r, i, h, p, rq, prefix, txt, ct;

  if (report_paranoia < 2)
    ct = "text/(xml|html)";
  else
    ct = NULL;

  url = my_encode(url);
  if (excluded_RE && ereg(string: url, pattern: excluded_RE, icase: 1))
    return -1;
  debug_print(level:3, 'URL=', url, '\n');
  for (h = 0; headers[h]; h ++)
  {
    foreach p (keys(flaws_and_patterns))
    {
      foreach prefix (make_list("", "nessus="))
      {
        if (isnull(postdata))
          rq = http_mk_req(item: url, port:port, method: meth, add_headers: make_array(headers[h], prefix+poison[p]));
        else
        {
          rq = http_mk_req(item: url, port:port, method: meth, data:postdata, add_headers: make_array(headers[h], prefix+poison[p]));
        }
        r = http_send_recv_req(req: rq, port:port, only_content: ct);
        if(isnull(r))
          return 0;

	# torture_cgi_audit_response cannot be called here (no poisoned parameter)
	txt = sanitize_utf16(body: r[2], headers: r[1]);
        txt = extract_pattern_from_resp(pattern: flaws_and_patterns[p], string: txt);
	if (txt)
        {
          torture_cgi_remember(port: port, url: url, response: r, cgi: cgi, vul: vul, method: meth, report: txt);
	  return 1;
        }
      }
    }
  }
  return -1;
}

set_test(func:@test_local);

port = torture_cgi_init(vul:'XH');

if (thorough_tests)
 e = make_list("pl", "php", "php3", "php4", "php5", "cgi", "asp", "aspx");
else
 e = NULL;

rep = run_injection_hdr(vul: "XH", ext_l: e);
if (rep) security_note(port: port, extra: rep);
