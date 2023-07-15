#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101846);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8000");
  script_bugtraq_id(99572);

  script_name(english:"EMC RSA Authentication Manager < 8.2 SP1 Patch 1 Token Profile Name Stored XSS (ESA-2017-068)");
  script_summary(english:"Checks the version of EMC RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote
host is prior to 8.2 SP1 Patch 1 (8.2.1.1). It is, therefore, affected
by a stored cross-site scripting (XSS) vulnerability due to a failure
to validate user-supplied input to names of token profiles before
returning them to users. An authenticated, remote attacker can exploit
this, via a specially crafted request, to execute arbitrary script
code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2017/Jul/25");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.2 SP1 Patch 1
(8.2.1.1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8000");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

fix = '8.2.1.1';
fix_display = "8.2 SP1 Patch 1";

if (version =~ "^[0-8]\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + report_url +
    '\n  Installed version : ' + version_display +
    '\n  Fixed version     : ' + fix_display +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
