#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160203);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/13");

  script_cve_id("CVE-2022-24112");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"Apache APISIX < 2.10.4 / 2.11.x < 2.12.1 RCE");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is missing a vendor-supplied update.");
  script_set_attribute(attribute:"description", value:
"The version of Apache APISIX installed on the remote host is prior to 2.10.4 or 2.11.x prior to 2.12.1. It is, 
therefore, affected by a remote code execution vulnerability due to flaw in the product's source code. An 
unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary code.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://packetstormsecurity.com/files/166228/Apache-APISIX-Remote-Code-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f54c8b3");
  # https://github.com/apache/apisix/blob/release/2.10/CHANGELOG.md#2104
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a86b6df0");
  # https://github.com/apache/apisix/blob/release/2.12/CHANGELOG.md#2121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a465d29");
  # https://github.com/apache/apisix/pull/6251
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f04566dc");
  # https://lists.apache.org/thread/lcdqywz8zy94mdysk7p3gfdgn51jmt94
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04f44e92");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache APISIX version 2.10.4, 12.12.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24112");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'APISIX Admin API default access token RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:apisix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_apisix_http_detect.nbin");
  script_require_keys("installed_sw/Apache APISIX");

  exit(0);
}
include('http.inc');
include('vcf.inc');

var port = get_http_port(default:9080);
var app_info = vcf::get_app_info(app:'Apache APISIX', port:port, service:TRUE);

var constraints = [
  {'fixed_version': '2.10.4'},
  {'min_version': '2.11', 'fixed_version':'2.12.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
