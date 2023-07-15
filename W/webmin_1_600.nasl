#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117602);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/05");

  script_cve_id(
    "CVE-2012-2981",
    "CVE-2012-2982",
    "CVE-2012-2983",
    "CVE-2012-4893"
  );
  script_bugtraq_id(55446, 66328);

  script_name(english:"Webmin <= 1.590 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Webmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Webmin install hosted on
the remote host is 1.590 or lower. It is, therefore, affected by 
multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/55446");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/66328");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Webmin 1.600 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4893");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-473");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Webmin /file/show.cgi Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);

get_kb_item_or_exit('www/'+port+'/webmin');
version = get_kb_item_or_exit('www/webmin/'+port+'/version', exit_code:1);
source = get_kb_item_or_exit('www/webmin/'+port+'/source', exit_code:1);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = "/";
install_url = build_url(port:port, qs:dir);

fix = "1.600";

if (ver_compare(ver:version, fix:"1.590", strict:FALSE) <= 0)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Version Source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE, xsrf:TRUE);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);