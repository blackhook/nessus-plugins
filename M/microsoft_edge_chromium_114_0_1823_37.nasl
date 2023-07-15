#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176816);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-2929",
    "CVE-2023-2930",
    "CVE-2023-2931",
    "CVE-2023-2932",
    "CVE-2023-2933",
    "CVE-2023-2934",
    "CVE-2023-2935",
    "CVE-2023-2936",
    "CVE-2023-2937",
    "CVE-2023-2938",
    "CVE-2023-2939",
    "CVE-2023-2940",
    "CVE-2023-2941",
    "CVE-2023-29345",
    "CVE-2023-33143"
  );
  script_xref(name:"IAVA", value:"2023-A-0274-S");

  script_name(english:"Microsoft Edge (Chromium) < 114.0.1823.37 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 114.0.1823.37. It is, therefore, affected
by multiple vulnerabilities as referenced in the June 2, 2023 advisory.

  - Out of bounds write in Swiftshader in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-2929)

  - Use after free in Extensions in Google Chrome prior to 114.0.5735.90 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2930)

  - Use after free in PDF in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to potentially
    exploit heap corruption via a crafted PDF file. (Chromium security severity: High) (CVE-2023-2931,
    CVE-2023-2932, CVE-2023-2933)

  - Out of bounds memory access in Mojo in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-2934)

  - Type Confusion in V8 in Google Chrome prior to 114.0.5735.90 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2935,
    CVE-2023-2936)

  - Inappropriate implementation in Picture In Picture in Google Chrome prior to 114.0.5735.90 allowed a
    remote attacker who had compromised the renderer process to spoof the contents of the Omnibox (URL bar)
    via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-2937, CVE-2023-2938)

  - Insufficient data validation in Installer in Google Chrome on Windows prior to 114.0.5735.90 allowed a
    local attacker to perform privilege escalation via crafted symbolic link. (Chromium security severity:
    Medium) (CVE-2023-2939)

  - Inappropriate implementation in Downloads in Google Chrome prior to 114.0.5735.90 allowed an attacker who
    convinced a user to install a malicious extension to bypass file access restrictions via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-2940)

  - Inappropriate implementation in Extensions API in Google Chrome prior to 114.0.5735.90 allowed an attacker
    who convinced a user to install a malicious extension to spoof the contents of the UI via a crafted Chrome
    Extension. (Chromium security severity: Low) (CVE-2023-2941)

  - Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability (CVE-2023-29345)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability (CVE-2023-33143)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2929");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2930");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2931");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2932");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2933");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2934");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2935");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2936");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2937");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2938");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2939");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2940");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2941");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29345");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-33143");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 114.0.1823.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2936");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/07");

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

var product_name = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Server 2012" >< product_name)
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (extended) {
	constraints = [
  		{ 'fixed_version' : '114.0.1823.37' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
