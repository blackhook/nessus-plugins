#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148832);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/01");

  script_name(english:"Nessus Agent Unsupported Version Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Nessus Agent.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable Nessus Agent on the
remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://www.tenable.com/downloads
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acfa0664");
  # https://tenable.my.salesforce.com/sfc/p/#300000000pZp/a/3a000000gPnK/Gu5PvUfKyV_gL0LdpNGgSdJ0PLKk15KPFcucY_BGlek
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1e381f2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Tenable Nessus Agent that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 Tenable Network Security, Inc.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin", "nessus_agent_installed_macos.nbin", "nessus_agent_installed_linux.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');
var now = get_kb_item("/tmp/start_time");
var constraints;

if (empty_or_null(now))
  now = int(gettimeofday());

vcf::check_granularity(app_info:app_info, sig_segments:3);

if (now > 1667174400) # 8.2.x EOL Mon Oct 31 2022 
 constraints = [
  { 'fixed_version' : '8.3.0' }
];
if (now > 1688083200) # 8.3.x EOL Fri Jun 30 2023
 constraints = [
  { 'fixed_version' : '10.0.0' }
];
if (now > 1701302400) # 10.0.x EOL Thu Nov 30 2023
 constraints = [
  { 'fixed_version' : '10.1.0' }
];
if (now > 1709164800) # 10.1.x EOL Thu Feb 29 2024
 constraints = [
  { 'fixed_version' : '10.2.0' }
];
if (now > 1725062400) # 10.2.x EOL Sat Aug 31 2024
 constraints = [
  { 'fixed_version' : '10.3.0' }
];
if (now > 1732924800) # 10.3.x EOL Sat Nov 30 2024
 constraints = [
  { 'fixed_version' : '10.4.0' }
];
if (now > 1745971200) # 10.4.x EOL Wed Apr 30 2025
 constraints = [
  { 'fixed_version' : '10.5.0' }
];

var matching_constraint = vcf::check_version(version:app_info.parsed_version, constraints:constraints);

if (!isnull(matching_constraint))
{
  var fix = matching_constraint.fixed_version;

  register_unsupported_product(product_name:app_info.app, version:app_info.version, cpe_base:'tenable:nessus_agent');

  vcf::report_results(app_info:app_info, fix:fix, severity:SECURITY_HOLE);
}
else vcf::audit(app_info);