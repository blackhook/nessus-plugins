#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176230);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id(
    "CVE-2023-2721",
    "CVE-2023-2722",
    "CVE-2023-2723",
    "CVE-2023-2724",
    "CVE-2023-2725",
    "CVE-2023-2726"
  );
  script_xref(name:"IAVA", value:"2023-A-0265-S");

  script_name(english:"Microsoft Edge (Chromium) < 113.0.1774.50 / 112.0.1722.84 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 113.0.1774.50 / 112.0.1722.84. It is,
therefore, affected by multiple vulnerabilities as referenced in the May 18, 2023 advisory.

  - Use after free in Navigation in Google Chrome prior to 113.0.5672.126 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical)
    (CVE-2023-2721)

  - Use after free in Autofill UI in Google Chrome on Android prior to 113.0.5672.126 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-2722)

  - Use after free in DevTools in Google Chrome prior to 113.0.5672.126 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-2723)

  - Type confusion in V8 in Google Chrome prior to 113.0.5672.126 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2724)

  - Use after free in Guest View in Google Chrome prior to 113.0.5672.126 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2725)

  - Inappropriate implementation in WebApp Installs in Google Chrome prior to 113.0.5672.126 allowed an
    attacker who convinced a user to install a malicious web app to bypass install dialog via a crafted HTML
    page. (Chromium security severity: Medium) (CVE-2023-2726)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2721");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2722");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2723");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2724");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2725");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2726");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 113.0.1774.50 / 112.0.1722.84 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2726");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

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

product_name = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Server 2012" >< product_name)
  audit(AUDIT_OS_SP_NOT_VULN);

var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (extended) {
	constraints = [
  		{ 'fixed_version' : '112.0.1722.84' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '113.0.1774.50' }
	];
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
