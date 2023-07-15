##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161717);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1853",
    "CVE-2022-1854",
    "CVE-2022-1855",
    "CVE-2022-1856",
    "CVE-2022-1857",
    "CVE-2022-1858",
    "CVE-2022-1859",
    "CVE-2022-1862",
    "CVE-2022-1863",
    "CVE-2022-1864",
    "CVE-2022-1865",
    "CVE-2022-1867",
    "CVE-2022-1868",
    "CVE-2022-1869",
    "CVE-2022-1870",
    "CVE-2022-1871",
    "CVE-2022-1872",
    "CVE-2022-1873",
    "CVE-2022-1874",
    "CVE-2022-1875",
    "CVE-2022-1876",
    "CVE-2022-26905",
    "CVE-2022-30127",
    "CVE-2022-30128"
  );

  script_name(english:"Microsoft Edge (Chromium) < 102.0.1245.30 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 102.0.1245.30. It is, therefore, affected
by multiple vulnerabilities as referenced in the May 31, 2022 advisory.

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30127. (CVE-2022-30128)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-30128. (CVE-2022-30127)

  - Use after free in Indexed DB in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2022-1853)

  - Use after free in ANGLE in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2022-1854)

  - Use after free in Messaging in Google Chrome prior to 102.0.5005.61 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2022-1855)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#may-31-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae294315");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1853");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1854");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1855");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1856");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1857");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1858");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1859");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1862");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1863");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1864");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1865");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1867");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1868");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1869");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1870");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1871");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1872");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1873");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1874");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1875");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1876");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26905");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30127");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30128");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 102.0.1245.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30128");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '102.0.1245.30' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
