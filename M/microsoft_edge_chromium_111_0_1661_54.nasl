#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173711);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2023-1528",
    "CVE-2023-1529",
    "CVE-2023-1530",
    "CVE-2023-1531",
    "CVE-2023-1532",
    "CVE-2023-1533",
    "CVE-2023-1534",
    "CVE-2023-28261",
    "CVE-2023-28286"
  );
  script_xref(name:"IAVA", value:"2023-A-0161-S");

  script_name(english:"Microsoft Edge (Chromium) < 111.0.1661.54 / 110.0.1587.78 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 111.0.1661.54 / 110.0.1587.78. It is,
therefore, affected by multiple vulnerabilities as referenced in the March 24, 2023 advisory.

  - Use after free in Passwords in Google Chrome prior to 111.0.5563.110 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1528)

  - Out of bounds memory access in WebHID in Google Chrome prior to 111.0.5563.110 allowed a remote attacker
    to potentially exploit heap corruption via a malicious HID device. (Chromium security severity: High)
    (CVE-2023-1529)

  - Use after free in PDF in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1530)

  - Use after free in ANGLE in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1531)

  - Out of bounds read in GPU Video in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1532)

  - Use after free in WebProtect in Google Chrome prior to 111.0.5563.110 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1533)

  - Out of bounds read in ANGLE in Google Chrome prior to 111.0.5563.110 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1534)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1528");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1529");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1530");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1531");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1532");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1533");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1534");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28261");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28286");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 111.0.1661.54 / 110.0.1587.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1534");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1529");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin", "smb_hotfixes.nasl");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var productname = get_kb_item("SMB/ProductName");
if ("Windows Server 2012" >< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (extended) {
	constraints = [
  		{ 'fixed_version' : '110.0.1587.78' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '111.0.1661.54' }
	];
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
