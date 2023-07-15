##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143423);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-8277");
  script_xref(name:"IAVB", value:"2020-B-0070-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Node.js 12.16.3 < 12.19.1 / 14.13.0 < 14.15.1 / 15.x < 15.2.1 DoS (November 2020 Security Releases)");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is at least 12.16.3 prior to 12.19.1, at least 14.13.0 prior to
14.15.1, or prior to 15.2.1. It is, therefore, affected by a denial-of-service (DoS) vulnerability as referenced in the
november-2020-security-releases advisory. An unauthenticated, remote attacker can exploit this, by getting the
application to resolve a DNS record with a larger number of responses, to cause the application to stop responding.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/november-2020-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ddc68d8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Node.js version 12.19.1 / 14.15.1 / 15.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8277");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nodejs_win_installed.nbin", "macosx_nodejs_installed.nbin");
  script_require_keys("installed_sw/Node.js");

  exit(0);
}

include('vcf.inc');

win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

app_info = vcf::get_app_info(app:'Node.js', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '12.16.3', 'fixed_version' : '12.19.1' },
  { 'min_version' : '14.13.0', 'fixed_version' : '14.15.1' },
  { 'min_version' : '15.0.0',  'fixed_version' : '15.2.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
