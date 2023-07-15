#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80960);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id("CVE-2014-8499");
  script_bugtraq_id(71018);

  script_name(english:"ManageEngine Password Manager Pro 6.5 < 7.1 Build 7105 Blind SQL Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a SQL
injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Password Manager
Pro between 6.5 (inclusive) and 7.1 Build 7105. It is, therefore,
affected by a blind SQL injection vulnerability due to a failure to
validate the 'SEARCH_ALL' parameter.");
  script_set_attribute(attribute:"see_also", value:"https://packetstormsecurity.com/files/129036");
  # http://www.manageengine.com/products/passwordmanagerpro/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b35a1c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Password Manager Pro version 7.1 build 7105 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8499");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:password_manager_pro");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_pmp_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Password Manager Pro");
  script_require_ports("Services/www", 7272);

  exit(0);
}

include('http_func.inc');
include('vcf_extras_zoho.inc');
include('http.inc');

var appname = 'ManageEngine Password Manager Pro';
var port    = get_http_port(default:7272, embedded:TRUE);

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  {'min_version' : '6500', 'fixed_version': '7105', 'fixed_display' : '7.1 Build 7105'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'sqli':TRUE}
);

