#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151576);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/26");

  script_cve_id("CVE-2021-29052");
  script_xref(name:"IAVA", value:"2021-A-0296-S");

  script_name(english:"Liferay Portal 7.3.x < 7.3.6 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"Liferay Portal 7.3.x prior to 7.3.6 is affected by an information disclosure vulnerability. The Data Engine
module in Liferay Portal 7.3.0 through 7.3.5 does not check permissions in
DataDefinitionResourceImpl.getSiteDataDefinitionByContentTypeByDataDefinitionKey, which allows remote authenticated
users to view DDMStructures via GET API calls.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/120743159
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d6729db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 7.3 CE GA7 (7.3.6) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:liferay_portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/liferay_portal");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'liferay_portal';
var port = get_http_port(default:8080);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

var constraints = [
  { 'min_version' : '7.3.0' , 'fixed_version' : '7.3.6' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
