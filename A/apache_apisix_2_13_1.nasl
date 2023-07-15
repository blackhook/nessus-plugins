##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161734);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/02");

  script_cve_id("CVE-2022-29266");

  script_name(english:"Apache APISIX < 2.13.1 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache APISIX installed on the remote host is prior to 2.13.1. It is, therefore, potentially affected by
an information disclosure vulnerability because the jwt-auth plugin has a security issue that leaks the user's secret
key because the error message returned from the dependency lua-resty-jwt contains sensitive information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/apisix/blob/release/2.13/CHANGELOG.md#2131");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/6qpfyxogbvn18g9xr8g218jjfjbfsbhr");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache APISIX version 2.13.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:apisix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_apisix_http_detect.nbin");
  script_require_keys("installed_sw/Apache APISIX", "Settings/ParanoidReport");

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:9080);
var app_info = vcf::get_app_info(app:'Apache APISIX', port:port, service:TRUE);

# Not able to check for patch, mitigation, or plugin
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'fixed_version': '2.13.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
