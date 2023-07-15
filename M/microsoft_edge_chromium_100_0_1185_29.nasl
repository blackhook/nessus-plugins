#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159465);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-1125",
    "CVE-2022-1127",
    "CVE-2022-1128",
    "CVE-2022-1129",
    "CVE-2022-1130",
    "CVE-2022-1131",
    "CVE-2022-1133",
    "CVE-2022-1134",
    "CVE-2022-1135",
    "CVE-2022-1136",
    "CVE-2022-1137",
    "CVE-2022-1138",
    "CVE-2022-1139",
    "CVE-2022-1143",
    "CVE-2022-1145",
    "CVE-2022-1146",
    "CVE-2022-24475",
    "CVE-2022-24523",
    "CVE-2022-26891",
    "CVE-2022-26894",
    "CVE-2022-26895",
    "CVE-2022-26900",
    "CVE-2022-26908",
    "CVE-2022-26909",
    "CVE-2022-26912"
  );

  script_name(english:"Microsoft Edge (Chromium) < 100.0.1185.29 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 100.0.1185.29. It is, therefore, affected
by multiple vulnerabilities as referenced in the April 1, 2022 advisory.

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-26891, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-24475)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability. (CVE-2022-24523)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26894, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26891)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26895, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26894)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2022-24475, CVE-2022-26891, CVE-2022-26894, CVE-2022-26900, CVE-2022-26908, CVE-2022-26909,
    CVE-2022-26912. (CVE-2022-26895)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#april-1-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?471a8cda");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1125");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1127");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1128");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1129");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1130");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1131");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1133");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1134");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1135");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1136");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1137");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1138");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1139");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1143");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1145");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-1146");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26894");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26895");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26900");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26908");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26909");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26912");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 100.0.1185.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26912");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/01");

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
  { 'fixed_version' : '100.0.1185.29' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
