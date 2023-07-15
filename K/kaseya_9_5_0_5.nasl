##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160888);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-20753");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/04");

  script_name(english:"Kaseya VSA < 9.3.0.35 / 9.4 < 9.4.0.36 / 9.5 < 9.5.0.5 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The Kaseya VSA instance installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Kaseya VSA installed on the remote host is affected by a remote code execution vulnerability. Kaseya VSA
RMM before R9.3 9.3.0.35, R9.4 before 9.4.0.36, and R9.5 before 9.5.0.5 allows unprivileged remote attackers to execute
PowerShell payloads on all managed devices. In January 2018, attackers actively exploited this vulnerability in the wild.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpdesk.kaseya.com/hc/en-gb/articles/360000333152");
  # https://blog.huntresslabs.com/deep-dive-kaseya-vsa-mining-payload-c0ac839a0e88
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bc61899");
  script_set_attribute(attribute:"solution", value:
"Update to Kaseya VSA version 9.3.0.35, 9.4.0.36, 9.5.0.5, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaseya:virtual_system_administrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaseya:vsa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '0.0', 'fixed_version' : '9.3.0.35'},
  { 'min_version' : '9.4', 'fixed_version' : '9.4.0.36'},
  { 'min_version' : '9.5', 'fixed_version' : '9.5.0.5'}
];

vcf::kaseya_vsa::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
