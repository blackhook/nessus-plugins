#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154327);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-37981",
    "CVE-2021-37982",
    "CVE-2021-37983",
    "CVE-2021-37984",
    "CVE-2021-37985",
    "CVE-2021-37986",
    "CVE-2021-37987",
    "CVE-2021-37988",
    "CVE-2021-37989",
    "CVE-2021-37990",
    "CVE-2021-37991",
    "CVE-2021-37992",
    "CVE-2021-37993",
    "CVE-2021-37994",
    "CVE-2021-37995",
    "CVE-2021-37996",
    "CVE-2021-42307"
  );
  script_xref(name:"IAVA", value:"2021-A-0491-S");

  script_name(english:"Microsoft Edge (Chromium) < 95.0.1020.30 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 95.0.1020.30. It is, therefore, affected
by multiple vulnerabilities as referenced in the October 21, 2021 advisory.

  - Use after free in PDF Accessibility in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37993)

  - Heap buffer overflow in Skia in Google Chrome prior to 95.0.4638.54 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-37981)

  - Use after free in Incognito in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37982)

  - Use after free in Dev Tools in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37983)

  - Heap buffer overflow in PDFium in Google Chrome prior to 95.0.4638.54 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37984)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#october-21-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d633bfe");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37981");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37982");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37983");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37984");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37985");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37986");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37987");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37988");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37989");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37990");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37991");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37992");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37993");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37994");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37995");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37996");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42307");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 95.0.1020.30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37993");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37981");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '95.0.1020.30' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
