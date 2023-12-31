#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93224);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2016-0269");
  script_bugtraq_id(91690);

  script_name(english:"IBM BigFix Server 9.2.x < 9.2.7.53 BES Gather XSS");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Server
running on the remote host is version 9.2.x prior to 9.2.7.53. It is,
therefore, affected by a reflected cross-site scripting (XSS)
vulnerability that exists in the BES gather function due to improper
validation of input before returning it to users. An unauthenticated,
remote attacker can exploit this, via a specially crafted URL, to
execute arbitrary script code in a user's browser session.

IBM BigFix was formerly known as Tivoli Endpoint Manager, IBM Endpoint
Manager, and IBM BigFix Endpoint Manager.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21985734");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Server version 9.2.7.53 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0269");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

# 9.2 is affected
if (version !~ '^9\\.2\\.')
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

if (version !~ "^(\d+\.){2,}\d+$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = "9.2.7.53";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = "";

  source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
  if (!isnull(source))
    report += '\n  Source            : ' + source;

  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE, xss:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
