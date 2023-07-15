#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42056);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/07");

  script_name(english:"CGI Generic Local File Inclusion");

  script_set_attribute(attribute:"synopsis", value:
"Confidential data may be disclosed on this server.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts CGI scripts that fail to adequately sanitize 
request strings.  By leveraging this issue, an attacker may be able 
to include a local file and disclose its content.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Remote_File_Inclusion");
  script_set_attribute(attribute:"solution", value:
"Restrict access to the vulnerable application. Contact the vendor 
for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(73, 78, 98, 473, 632, 714, 727, 928, 929);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl", "torture_cgi_load_estimation1.nasl");
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

## Check that the interpretor are working ##
exclcgi = NULL;
srcRE = 'RE:';

if (broken_php_interpretor(port: port, vul: "WL"))
  exclcgi += '|\\.php[3-5]?$';
else
  srcRE += '<\\?php|';

if (broken_asp_interpretor(port: port, vul: "WL"))
  exclcgi += '|\\.aspx?$';
else
  srcRE += '<%@ +LANGUAGE=.* %>|';

srcRE += 'use +CGI|\\.CreateObject *\\ *\\( *"';
if (exclcgi) exclcgi = substr(exclcgi, 1);

########

flaws_and_patterns = make_array(
"FILENAME",	srcRE
); 

if (thorough_tests)
  foreach k (make_list("FILENAME%00.html", "FILENAME%00.jpg","FILENAME/."))
     flaws_and_patterns[k] = srcRE;


FP_pattern = "RE:<!-- +<\?php .*\?> *-->";

port = torture_cgi_init(vul:'WL');


report = torture_cgis(port: port, vul: "WL", exclude_cgi: exclcgi);

if (strlen(report) > 0)
{
  security_warning(port:port, extra: report);
}
