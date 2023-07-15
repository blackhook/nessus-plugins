#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154235);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/04");

  script_cve_id("CVE-2021-22959", "CVE-2021-22960");
  script_xref(name:"IAVB", value:"2021-B-0059-S");

  script_name(english:"Node.js Multiple Vulnerabilities (October 12th 2021 Security Releases)");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 12.22.7, 14.18.1 or 16.11.1. It is, therefore,
affected by multiple HTTP smuggling vulnerabilities. An unauthenticated, remote attack could exploit these to bypass 
security controls, gain unauthorized access to sensitive data and directly compromise other application users.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/oct-2021-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dff48d51");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 12.22.7, 14.18.1, 16.11.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22959");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated')) 
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  {'min_version': '12.0.0', 'fixed_version': '12.22.7'},
  {'min_version': '14.0.0', 'fixed_version': '14.18.1'},
  {'min_version': '16.0.0', 'fixed_version': '16.11.1'},
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
