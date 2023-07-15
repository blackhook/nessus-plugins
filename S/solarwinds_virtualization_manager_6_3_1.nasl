#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154954);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2016-3643");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"SolarWinds Virtualization Manager <= 6.3.1 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote SolarWinds Virtualization Manager server is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote SolarWinds Virtualization Manager server is affected by a privilege escalation vulnerability. SolarWinds
Virtualization Manager 6.3.1 and earlier allow local users to gain privileges by leveraging a misconfiguration of sudo,
as demonstrated by sudo cat /etc/passwd.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://packetstormsecurity.com/files/137487/Solarwinds-Virtualization-Manager-6.3.1-Privilege-Escalation.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ba20df0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Virtualization Manager version 6.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:virtualization_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_virtualization_manager_detect.nbin");
  script_require_keys("installed_sw/SolarWinds Virtualization Manager");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'SolarWinds Virtualization Manager', port:port);

var constraints = [
  { 'fixed_version' : '6.3.2' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

