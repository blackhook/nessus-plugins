#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151494);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-30116", "CVE-2021-30119", "CVE-2021-30120");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0033");

  script_name(english:"Kaseya VSA < 9.5.7a Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The Kaseya VSA instance installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Kaseya VSA installed on the remote host is affected by multiple vulnerabilities as 
referenced in the vendor advisory:

  - Credentials leak and business logic flaw. (CVE-2021-30116)

  - Cross-Site Scripting vulnerability (XSS). (CVE-2021-30119)

  - 2FA Authentication bypass. (CVE-2021-30120)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpdesk.kaseya.com/hc/en-gb/articles/4403785889041");
  script_set_attribute(attribute:"see_also", value:"https://www.kaseya.com/potential-attack-on-kaseya-vsa/");
  script_set_attribute(attribute:"solution", value:
"Update to Kaseya VSA version 9.5.7a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30116");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaseya:virtual_system_administrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaseya:vsa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kaseya_vsa_detect.nbin");
  script_require_keys("installed_sw/Kaseya Virtual System Administrator");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

  var port = get_http_port(default:443);
  var app_info = vcf::get_app_info(app:'Kaseya Virtual System Administrator', port:port, webapp:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '9.5.7.2994'}
];

vcf::kaseya_vsa::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
