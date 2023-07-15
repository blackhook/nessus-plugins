##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143156);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-8075",
    "CVE-2020-16012",
    "CVE-2020-16014",
    "CVE-2020-16015",
    "CVE-2020-16018",
    "CVE-2020-16022",
    "CVE-2020-16023",
    "CVE-2020-16024",
    "CVE-2020-16025",
    "CVE-2020-16026",
    "CVE-2020-16027",
    "CVE-2020-16028",
    "CVE-2020-16029",
    "CVE-2020-16030",
    "CVE-2020-16031",
    "CVE-2020-16032",
    "CVE-2020-16033",
    "CVE-2020-16034",
    "CVE-2020-16036"
  );

  script_name(english:"Microsoft Edge (Chromium) < 87.0.664.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 87.0.664.41. It is, therefore, affected
by multiple vulnerabilities as referenced in the ADV200002-11-19-2020 advisory.

  - Adobe Flash Player version 32.0.0.192 and earlier versions have a Same Origin Policy Bypass vulnerability.
    Successful exploitation could lead to Information Disclosure in the context of the current user.
    (CVE-2019-8075)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?083510ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 87.0.664.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16029");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-16025");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '87.0.664.41' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
