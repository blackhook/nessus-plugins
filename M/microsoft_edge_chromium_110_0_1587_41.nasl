#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171268);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2023-0696",
    "CVE-2023-0697",
    "CVE-2023-0698",
    "CVE-2023-0699",
    "CVE-2023-0700",
    "CVE-2023-0701",
    "CVE-2023-0702",
    "CVE-2023-0703",
    "CVE-2023-0704",
    "CVE-2023-0705",
    "CVE-2023-21794",
    "CVE-2023-23374"
  );
  script_xref(name:"IAVA", value:"2023-A-0074-S");
  script_xref(name:"IAVA", value:"2023-A-0075-S");

  script_name(english:"Microsoft Edge (Chromium) < 110.0.1587.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 110.0.1587.41. It is, therefore, affected
by multiple vulnerabilities as referenced in the February 9, 2023 advisory.

  - Type confusion in V8 in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0696)

  - Inappropriate implementation in Full screen mode in Google Chrome on Android prior to 110.0.5481.77
    allowed a remote attacker to spoof the contents of the security UI via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-0697)

  - Out of bounds read in WebRTC in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to perform
    an out of bounds memory read via a crafted HTML page. (Chromium security severity: High) (CVE-2023-0698)

  - Use after free in GPU in Google Chrome prior to 110.0.5481.77 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page and browser shutdown. (Chromium security severity: Medium)
    (CVE-2023-0699)

  - Inappropriate implementation in Download in Google Chrome prior to 110.0.5481.77 allowed a remote attacker
    to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-0700)

  - Heap buffer overflow in WebUI in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via UI
    interaction . (Chromium security severity: Medium) (CVE-2023-0701)

  - Type confusion in Data Transfer in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who
    convinced a user to engage in specific UI interactions to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-0702)

  - Type confusion in DevTools in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who convinced
    a user to engage in specific UI interactions to potentially exploit heap corruption via UI interactions.
    (Chromium security severity: Medium) (CVE-2023-0703)

  - Insufficient policy enforcement in DevTools in Google Chrome prior to 110.0.5481.77 allowed a remote
    attacker to bypass same origin policy and proxy settings via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0704)

  - Integer overflow in Core in Google Chrome prior to 110.0.5481.77 allowed a remote attacker who had one a
    race condition to potentially exploit heap corruption via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0705)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0696");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0697");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0698");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0699");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0700");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0701");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0702");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0703");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0704");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0705");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21794");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 110.0.1587.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23374");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0703");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '110.0.1587.41' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
