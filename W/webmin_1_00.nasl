#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108543);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2002-1947", "CVE-2002-2360");
  script_bugtraq_id(5936, 5591);

  script_name(english:"Webmin 0.21 <= 1.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Webmin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Webmin install hosted on
the remote host is between versions 0.21 and 1.0. It is, therefore,
affected by multiple vulnerabilities:

  - Versions 0.21 through 1.00 use the same SSL key for 
    all installations, which may allow attackers to 
    eavesdrop on traffic. (CVE-2002-1947)

  - A remote code execution vulnerability via 
    remote_foregin_require and remote_foreign_call requests.
    (CVE-2002-2360)");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/5591");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/5936");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/changes.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Webmin 1.010 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");

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

fix = "1.010";

if( 
    version =~ "0.[2-9]" ||
    version =~ "1.00"
  )
{

  report =
    '\n  URL               : ' + install_url +
    '\n  Version Source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
