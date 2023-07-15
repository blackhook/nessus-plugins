#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165346);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2022-40300");
  script_xref(name:"IAVA", value:"2022-A-0383-S");

  script_name(english:"ManageEngine Password Manager Pro < 12.1 Build 12121 SQLi");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of ManageEngine Password Manager Pro prior to 12.1 Build 12121. It is, therefore,
affected by a SQL injection vulnerability. An unauthenticated, remote attacker can exploit this to inject or manipulate
SQL queries in the back-end database, resulting in the disclosure or manipulation of arbitrary data.");
  # https://www.manageengine.com/products/passwordmanagerpro/advisory/cve-2022-40300.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac5d4f85");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Password Manager Pro version 12.1 Build 12121 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40300");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:password_manager_pro");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_pmp_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Password Manager Pro");
  script_require_ports("Services/www", 7272);

  exit(0);
}

include('vcf_extras_zoho.inc');
include('http.inc');

var appname = 'ManageEngine Password Manager Pro';
var port    = get_http_port(default:7272, embedded:TRUE);

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  { 'fixed_version' : '12121', 'fixed_display' : '12.1 Build 12121' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);

