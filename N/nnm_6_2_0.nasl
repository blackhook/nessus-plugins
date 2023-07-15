#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170688);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id(
    "CVE-2021-23369",
    "CVE-2021-23383",
    "CVE-2022-24785",
    "CVE-2022-31129"
  );

  script_name(english:"Nessus Network Monitor < 6.2.0 Multiple Vulnerabilities (TNS-2022-28)");

  script_set_attribute(attribute:"synopsis", value:
"A vulnerability scanner installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Nessus Network Monitor (NNM) installed on the remote host is
prior to 6.2.0. It is, therefore, affected by multiple vulnerabilities in
third-party software. Out of caution and in line with best practice, Tenable has
opted to upgrade these components to address the potential impact of the issues.
Nessus Network Monitor 6.2.0 updates moment.js to version 2.29.4 and handlebars
to version 4.7.7 to address the identified vulnerabilities.

Note that Nessus has not tested for this issue but has instead relied only on
the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2022-28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nessus Network Monitor version 6.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

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
  { 'fixed_version' : '6.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

