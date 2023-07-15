##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145549);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2020-26980",
    "CVE-2020-26981",
    "CVE-2020-26982",
    "CVE-2020-26983",
    "CVE-2020-26984",
    "CVE-2020-26985",
    "CVE-2020-26986",
    "CVE-2020-26987",
    "CVE-2020-26988",
    "CVE-2020-26992",
    "CVE-2020-26993",
    "CVE-2020-26994",
    "CVE-2020-26995",
    "CVE-2020-26996",
    "CVE-2020-28383"
  );

  script_name(english:"Siemens JT2Go < 13.1.0 Multiple Vulnerabilities (SSA-622830)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Siemens JT2Go installed on the remote Windows hosts is prior to 13.1.0. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - A vulnerability has been identified in JT2Go (All versions < V13.1.0), Teamcenter Visualization (All
    versions < V13.1.0). Affected applications lack proper validation of user-supplied data when parsing JT
    files. A crafted JT file could trigger a type confusion condition. An attacker could leverage this
    vulnerability to execute code in the context of the current process. (CVE-2020-26980)

  - A vulnerability has been identified in JT2Go (All versions < V13.1.0), Teamcenter Visualization (All
    versions < V13.1.0). Affected applications lack proper validation of user-supplied data when parsing CG4
    and CGM files. This could result in an out of bounds write past the end of an allocated structure. An
    attacker could leverage this vulnerability to execute code in the context of the current process.
    (CVE-2020-26982)

  - A vulnerability has been identified in JT2Go (All versions < V13.1.0), Teamcenter Visualization (All
    versions < V13.1.0). Affected applications lack proper validation of user-supplied data when parsing PDF
    files. This could result in an out of bounds write past the end of an allocated structure. An attacker
    could leverage this vulnerability to execute code in the context of the current process. (CVE-2020-26983)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://cert-portal.siemens.com/productcert/pdf/ssa-622830.pdf");
  script_set_attribute(attribute:"solution", value:
"Update JT2Go to version 13.1.0 (File version 13.1.0.20328)");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28383");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-26996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:siemens:jt2go");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("siemens_jt2go_win_installed.nbin");
  script_require_keys("installed_sw/Siemens JT2Go");

  exit(0);
}


include('vcf.inc');

var app_info = vcf::get_app_info(app:'Siemens JT2Go', win_local:TRUE);

var constraints = [
  { 'fixed_version': '13.1.0.20328', 'fixed_display':'13.1.0 (File version 13.1.0.20328)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
