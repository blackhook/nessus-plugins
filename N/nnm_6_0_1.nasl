##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161211);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/03");

  script_cve_id(
    "CVE-2021-3711",
    "CVE-2021-3712",
    "CVE-2021-4160",
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184",
    "CVE-2022-0778"
  );

  script_name(english:"Nessus Network Monitor < 6.0.1 Multiple Vulnerabilities (TNS-2022-10)");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Network Monitor (NNM) installed on the remote host is prior to 6.0.1. It is, therefore, affected
by multiple vulnerabilities in third-party software.

  Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
  version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor version 6.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3711");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '6.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

