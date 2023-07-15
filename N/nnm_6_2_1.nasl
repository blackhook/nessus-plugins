#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175428);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/12");

  script_cve_id(
    "CVE-2021-45960",
    "CVE-2021-46143",
    "CVE-2022-4203",
    "CVE-2022-4304",
    "CVE-2022-4450",
    "CVE-2022-22822",
    "CVE-2022-22823",
    "CVE-2022-22824",
    "CVE-2022-22825",
    "CVE-2022-22826",
    "CVE-2022-22827",
    "CVE-2022-23852",
    "CVE-2022-23990",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25314",
    "CVE-2022-25315",
    "CVE-2022-40674",
    "CVE-2023-0215",
    "CVE-2023-0216",
    "CVE-2023-0217",
    "CVE-2023-0401"
  );

  script_name(english:"Nessus Network Monitor < 6.2.1 Multiple Vulnerabilities (TNS-2023-19)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Tenable NNM installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Nessus Network Monitor running on the remote host is prior to 6.2.1. It is,
therefore, affected by multiple vulnerabilities as referenced in the TNS-2023-19 advisory.

  - Nessus Network Monitor leverages third-party software to help provide underlying functionality. Several of
    the third-party components (OpenSSL, expat) were found to contain vulnerabilities, and updated versions
    have been made available by the providers.    Out of caution and in line with best practice, Tenable has
    opted to upgrade these components to address the potential impact of the issues. Nessus Network Monitor
    6.2.1 updates OpenSSL to version 3.0.8 and expat to version 2.5.0 to address the identified
    vulnerabilities. Tenable has released Nessus Network Monitor 6.2.1 to address these issues. The
    installation files can be obtained from the Tenable Downloads Portal
    (https://www.tenable.com/downloads/nessus-network-monitor). (CVE-2021-45960, CVE-2021-46143,
    CVE-2022-22822, CVE-2022-22823, CVE-2022-22824, CVE-2022-22825, CVE-2022-22826, CVE-2022-22827,
    CVE-2022-23852, CVE-2022-23990, CVE-2022-25235, CVE-2022-25236, CVE-2022-25314, CVE-2022-25315,
    CVE-2022-40674, CVE-2022-4203, CVE-2022-4304, CVE-2022-4450, CVE-2023-0215, CVE-2023-0216, CVE-2023-0217,
    CVE-2023-0401)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.tenable.com/releasenotes/Content/nnm/2023nnm.htm");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2023-19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor 6.2.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45960");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-25315");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nnm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nnm_installed_win.nbin", "nnm_installed_nix.nbin");
  script_require_keys("installed_sw/Tenable NNM", "Host/nnm_installed");

  exit(0);
}

include('vcf.inc');

var app_name = 'Tenable NNM';

var app_info = vcf::get_app_info(app:app_name);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'max_version' : '6.2.0', 'fixed_version' : '6.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
