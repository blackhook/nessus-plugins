#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55904);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"CGI Generic Script Injection (quick test)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to cross-site scripting attacks.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts one or more CGI scripts that fail to
adequately sanitize request strings.  By leveraging this issue, an
attacker may be able to inject malicious code in an existing 'script'
block and cause arbitrary script code to be executed in a user's
browser within the security context of the affected site.  These XSS
vulnerabilities are likely to be 'non persistent' or 'reflected'.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross_site_scripting#Non-persistent");
  # https://blog.jeremiahgrossman.com/2009/06/results-unicode-leftright-pointing.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9a0369");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application.  Contact the vendor
for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(20, 74, 79, 80, 81, 83, 86, 116, 442, 692, 712, 722, 725, 751, 801, 811, 928, 931);

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/04");

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

global_var	XSS_magic_str;

function torture_cgi_response_post_check(resp)
{
  local_var	page, len, js_idx, c, idx, len_magic1, found, j, vbs;

  page = tolower(resp[2]);
  len = strlen(resp[2]);
  page += crap(data: ' ', length: 8);
  js_idx = -1; found = 0;
  len_magic1 = strlen(XSS_magic_str) - 1;

  idx = 0;
  while (1)
  {
    idx = stridx(page, XSS_magic_str, idx);
    if (idx < 0)
    {
      debug_print('torture_cgi_response_post_check: <script></script> not found\n');
      return 1;	# <script> </script> not found
    }
    j = stridx(page, '<script');
    if (j >= 0 && j <= idx)
    {
      j = stridx(page, '</script', idx);
      if (j >= 0) break;
    }
    idx += len_magic1;
  }

  for (i = 0; i < len; i ++)
  {
    if (js_idx >= 0)
    {
      if ( (page[i] == '/' && page[i+1] == '/') || 
      	   (vbs && (page[i] == '\'' || substr(page, i, i+2) == 'rem') ) )
      {
        # Swallow Javascript/VBScript comment
        while(i < len && page[i] != '\n') i ++;
      }
      else if (substr(page, i, i + 7) == '</script')
      {
        c = page[i + 8];

        if (c == '>' || c == ' ' || c == '\t' || c == '\n')
        {
	  if (XSS_magic_str >< substr(page, js_idx, i)) return 0;
        }
        while (i < len && page[i] != '>') i ++;
        js_idx = -1;
      }
    }
    else if (page[i] == '"' || page[i] == "'")
    {
      # Swallow strings
      c = page[i];
      i ++;
      while (i < len && page[i] != c)
      {
        if (page[i] == '\\') i ++;
	i ++;
      }
    }
    else if (page[i] == '<')
    {
      j = i;
      # Swallow comment
      # HTML comments inside script blocks are ignored by new  browsers.
      if (page[i+1] == '!' && page[i+2] == '-' && page[i+3] == '-')
      {
        i += 4;
        while (i < len)
          if ( page[i] == '-' && page[i+1] == '-' && page[i+2] == '>')
	  {
	    i += 3;
	    break;
	  }
	  else i++;
      }
      else if (substr(page, i+1, i+6) == 'script')
      {
        c = page[i + 7];
        if (c == '>' || c == ' ' || c == '\t' || c == '\n')
        {
          js_idx = i + 7;
        }
	i += 7;
      }
      while (i < len && page[i] != '>') i ++;
      if (substr(page, j, i) =~ '(type=[\'"]?text/|language)=[\'"]?vbscript')
        vbs = 1;
      else
        vbs = 0;
    }
  }
  return 1;
}

set_post_check_cb(func:@torture_cgi_response_post_check);


XSS_magic_str = 'msgbox("foo");window.alert(\'bar\');';

flaws_and_patterns = make_array(
  XSS_magic_str,	'ST:' + XSS_magic_str
);

port = torture_cgi_init(vul:'XI');


if (get_kb_item(strcat("www/", port, "/generic_xss")))
  exit(0, 'The web server on port '+port+' is prone to generic cross-site scripting attaks.');
# if (stop_at_first_flaw == "port" && ! thorough_tests && get_kb_item(strcat("www/", port, "/XSS"))) exit(0);

if (get_kb_item("Settings/PCI_DSS") || report_paranoia < 2)
  ct = "text/(xml|html)";
else
  ct = NULL;
report = torture_cgis(port: port, vul: "XI", only_content: ct, injectable_only: INJECTABLE_TEXT, follow_redirect: 2);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
