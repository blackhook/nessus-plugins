#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76144);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id(
    "CVE-2013-5017",
    "CVE-2014-1650",
    "CVE-2014-1651",
    "CVE-2014-1652"
  );
  script_bugtraq_id(
    67752,
    67753,
    67754,
    67755
  );
  script_xref(name:"CERT", value:"719172");

  script_name(english:"Symantec Web Gateway < 5.2.1 Multiple Vulnerabilities (SYM14-010)");
  script_summary(english:"Checks SWG version");

  script_set_attribute(attribute:"synopsis", value:
"A web security application hosted on the remote web server is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote web server
is hosting a version of Symantec Web Gateway prior to version 5.2.1.
It is, therefore, affected by the following vulnerabilities :

  - A remote command execution flaw exists with the
    'SNMPConfig.php' where user input is not properly
    sanitized. This could allow a remote attacker to execute
    arbitrary commands. (CVE-2013-5017)

  - A SQL injection flaw exists with the 'user.php' where
    user input is not properly sanitized before using it in
    SQL queries. This could allow an authenticated, remote
    attacker to manipulate or disclose arbitrary data.
    (CVE-2014-1650)

  - A SQL injection flaw exists with the 'clientreport.php'
    where user input is not properly sanitized before using
    it in SQL queries. This could allow an authenticated,
    remote attacker to manipulate or disclose arbitrary
    data. (CVE-2014-1651)

  - A cross site scripting flaw exists due to not validating
    input for multiple, unspecified report parameters before
    returning it to the users. This could allow a context
    dependent attacker with a specifically crafted request
    to execute arbitrary script code within the trust
    relationship between the browser and server.
    (CVE-2014-1652)");
  # https://support.symantec.com/en_US/article.SYMSA1297.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62cbefd1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Web Gateway 5.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5017");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);

install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);
dir = install['dir'];
url = build_url(port:port, qs:dir);

ver = install['ver'];
if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Web Gateway', url);

fix = '5.2.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Web Gateway', url, ver);

