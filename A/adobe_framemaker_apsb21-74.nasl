#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153471);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id(
    "CVE-2021-39829",
    "CVE-2021-39830",
    "CVE-2021-39831",
    "CVE-2021-39832",
    "CVE-2021-39833",
    "CVE-2021-39834",
    "CVE-2021-39835",
    "CVE-2021-40697"
  );
  script_xref(name:"IAVB", value:"2021-B-0051-S");

  script_name(english:"Adobe FrameMaker 2020 < 16.0.3 (2020.0.3) / Adobe FrameMaker 2019 < 15.0.8 (2020.0.8) Multiple Vulnerabilities (APSB21-74)");

  script_set_attribute(attribute:"synopsis", value:
"The remote install of Adobe FrameMaker has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe FrameMaker installed on the remote Windows host is either 2020 prior to 16.0.2 (2020.0.2) or
2019 prior to 15.0.8. It is, therefore, affected by multiple vulnerabiliites:

  - Unspecified out of bounds write error that allows arbitrary code execution. (CVE-2021-39829 , CVE-2021-39831)

  - Unspecified buffer overflow that allows arbitrary code execution. (CVE-2021-39830, CVE-2021-39832)

  - Unspecified out of bounds read error that allows arbitrary file system read (CVE-2021-39833 , CVE-2021-39834)

If running FrameMaker 2019, the Hotfix listed in the see also will need to be applied.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/framemaker/apsb21-74.html");
  # https://helpx.adobe.com/framemaker/kb/fix-for-out-of-bound-write-remote-code-execution-in-framemaker.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d65a98e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe FrameMaker 16.0.3 (2020.0.3) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:framemaker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_framemaker_installed.nbin");
  script_require_keys("installed_sw/Adobe FrameMaker", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Adobe FrameMaker', win_local:TRUE);

# Due to unique hotfix scenario, we are temporarily adding this paranoid condition
if (app_info['version'] =~ "15\.0\.8([^0-9]|$)" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'Adobe FrameMaker');

# 16.0.3 (aka 2020.0.3)
var constraints = [
    {'fixed_version':'15.0.9', 'fixed_display':'15.0.8 / 2019.0.8 / 2019 Release Update 8 + hotfix'},
    {'min_version':'16.0.0', 'fixed_version':'16.0.3', 'fixed_display':'2020.0.3 / 16.0.3 / 2020 Release Update 3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
