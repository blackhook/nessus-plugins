#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159914);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id("CVE-2020-13945");

  script_name(english:"Apache APISIX 1.2 <= 1.5 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache APISIX installed on the remote host is 1.2 prior to or equal to 1.5. It is, therefore, affected by
an information disclosure vulnerability. An authenticated, remote attacker could exploit this to access Apache APISIX
management data.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://lists.apache.org/thread/m0hzrdzrjy6k2obvbzr459w9lq4ygm33");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache APISIX version 2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13945");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'APISIX Admin API default access token RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:apisix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_apisix_http_detect.nbin");
  script_require_keys("installed_sw/Apache APISIX");

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:9080);
var app_info = vcf::get_app_info(app:'Apache APISIX', port:port, service:TRUE);
var constraints = [{'min_version':'1.2', 'max_version':'1.5', 'fixed_display': '2.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);