#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(118937);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id(
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2018-7166",
    "CVE-2018-12115"
  );
  script_bugtraq_id(103766, 104442, 105127);

  script_name(english:"Node.js Multiple Vulnerabilities (August 2018 Security Releases)");
  script_summary(english:"Checks the Node.js version.");

  script_set_attribute(attribute:"synopsis", value:
"Node.js - JavaScript run-time environment is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Node.js installed on the remote host is 6.x prior to 6.14.4, 8.x prior to 8.11.4 or 10.x prior to
10.9.0. It is, therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://nodejs.org/en/blog/vulnerability/august-2018-security-releases/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f738f917");
  script_set_attribute(attribute:"solution", value:
"Upgrade Node.js to a recommended by vendor version or above.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nodejs:node.js");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.14.4' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.11.4' },
  { 'min_version' : '10.0.0', 'fixed_version' : '10.9.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
