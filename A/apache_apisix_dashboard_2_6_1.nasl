##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161978);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/13");

  script_cve_id("CVE-2021-33190");

  script_name(english:"Apache APISIX Dashboard 2.6 < 2.6.1 Authentication Bypass");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache APISIX Dashboard installed on the remote host is 2.6 prior to 2.6.1. It is, therefore, affected 
by an authentication bypass vulnerability. In Apache APISIX Dashboard version 2.6, we changed the default value of 
listen host to 0.0.0.0 in order to facilitate users to configure external network access. In the IP allowed list 
restriction, a risky function was used for the IP acquisition, which made it possible to bypass the network limit. At 
the same time, the default account and password are fixed. Ultimately these factors lead to the issue of security risks. 
This issue is fixed in APISIX Dashboard 2.6.1.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/zyyzycodf2mz9qwgkz3pp8jgmrtmvopo");
  # https://github.com/apache/apisix-dashboard/blob/release/2.6.1/CHANGELOG.md#261
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13dac9a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache APISIX Dashboard version 2.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33190");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:apisix_dashboard");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_apisix_dashboard_detect.nbin");
  script_require_keys("installed_sw/Apache APISIX Dashboard");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:9000);
var app_info = vcf::get_app_info(app:'Apache APISIX Dashboard', port:port, webapp:TRUE);
var constraints = [{ 'min_version': '2.6.0', 'fixed_version': '2.6.1'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);