#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174524);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2023-2033", "CVE-2023-29334");
  script_xref(name:"IAVA", value:"2023-A-0204-S");
  script_xref(name:"IAVA", value:"2023-A-0203-S");
  script_xref(name:"IAVA", value:"2023-A-0232");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/08");

  script_name(english:"Microsoft Edge (Chromium) < 112.0.1722.48 ");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 112.0.1722.48. It is, therefore, affected
by a vulnerability as referenced in the April 15, 2023 advisory.

  - Type confusion in V8 in Google Chrome prior to 112.0.5615.121 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-2033)

  - A spoofing vulnerability could allow an attacker to bypass the Edge security warning message feature.
    (CVE-2023-29334)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-2033");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 112.0.1722.48 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-2033");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

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
  		{ 'fixed_version' : '112.0.1722.48' }
	];
} else {
  constraints = [
      { 'fixed_version' : '109.0.1518.100' } 
  ];
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
