#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154232);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-37701",
    "CVE-2021-37712",
    "CVE-2021-37713",
    "CVE-2021-39134",
    "CVE-2021-39135"
  );

  script_name(english:"Node.js Multiple Vulnerabilities (August 31st 2021 Security Releases)");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is prior to 12.22.6 or 14.17.6. It is, therefore,
affected by multiple remote code execution vulnerabilities in various components due to insufficient validation of user 
input. An unauthenticated, remote attacker can exploit this to bypass authentication and execute arbitrary commands. 
Additional impacts of these vulnerabilities include arbitrary file writing and creation. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/aug-2021-security-releases2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68e6eca3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 12.22.6, 14.17.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
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
  {'min_version': '12.0.0', 'fixed_version': '12.22.6'},
  {'min_version': '14.0.0', 'fixed_version': '14.17.6'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
