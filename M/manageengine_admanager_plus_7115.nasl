#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158361);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id("CVE-2021-42002");

  script_name(english:"ManageEngine ADManager Plus < Build 7115 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An Active Directory management application running on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Zoho ManageEngine ADManager Plus before version 7.1 Build 7115 is affected by a filter bypass flaw which allows an
unauthenticated, remote attacker to upload a file to execute arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.manageengine.com/products/ad-manager/release-notes.html#7115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8e0cba4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine ADManager Plus version 7.1 build 7115 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_admanager_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_admanager_plus_detect.nbin");
  script_require_keys("installed_sw/ManageEngine ADManager Plus");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf_extras_zoho.inc');
include('http.inc');

var port = get_http_port(default:8080);
var app = 'ManageEngine ADManager Plus';
var app_info = vcf::zoho::fix_parse::get_app_info(app:app, webapp:TRUE, port:port);

var constraints = [
  {'fixed_version': '7115.0', 'fixed_display': '7.1, Build 7115'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
