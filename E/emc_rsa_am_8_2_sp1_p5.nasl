#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104380);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-14373");
  script_bugtraq_id(101605);

  script_name(english:"EMC RSA Authentication Manager < 8.2 SP1 Patch 5 Reflected Cross-Site Scripting (ESA-2017-134)");
  script_summary(english:"Checks the version of EMC RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote
host is prior to 8.2 SP1 Patch 5 (8.2.1.5). It is, therefore, affected
by a reflected cross-site scripting vulnerability via an argument in
the HTTP POST request. Attackers could potentially exploit this
vulnerability to execute arbitrary HTML or JavaScript code in the
user's browser session in the context of the affected
RSA Authentication Manager application.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Oct/62");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.2 SP1 Patch 5
(8.2.1.5) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_am_detect.nbin");
  script_require_keys("www/emc_rsa_am");
  script_require_ports("Services/www", 7004);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/emc_rsa_am");

app_name = "EMC RSA Authentication Manager";
port = get_http_port(default:7004);
kb_prefix = "www/"+port+"/emc_rsa_am/";

report_url = get_kb_item_or_exit(kb_prefix + "url");
version = get_kb_item_or_exit(kb_prefix + "version");
version_display = get_kb_item_or_exit(kb_prefix + "version_display");

fix = '8.2.1.5';
fix_display = "8.2 SP1 Patch 5";

if (version =~ "^[0-8]\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + report_url +
    '\n  Installed version : ' + version_display +
    '\n  Fixed version     : ' + fix_display +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
