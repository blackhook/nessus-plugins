#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172572);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2023-1213",
    "CVE-2023-1214",
    "CVE-2023-1215",
    "CVE-2023-1216",
    "CVE-2023-1217",
    "CVE-2023-1218",
    "CVE-2023-1219",
    "CVE-2023-1220",
    "CVE-2023-1221",
    "CVE-2023-1222",
    "CVE-2023-1223",
    "CVE-2023-1224",
    "CVE-2023-1228",
    "CVE-2023-1229",
    "CVE-2023-1230",
    "CVE-2023-1231",
    "CVE-2023-1232",
    "CVE-2023-1233",
    "CVE-2023-1234",
    "CVE-2023-1235",
    "CVE-2023-1236"
  );
  script_xref(name:"IAVA", value:"2023-A-0131-S");

  script_name(english:"Microsoft Edge (Chromium) < 111.0.1661.41 / 110.0.1587.69 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 111.0.1661.41 / 110.0.1587.69. It is,
therefore, affected by multiple vulnerabilities as referenced in the March 13, 2023 advisory.

  - Use after free in Swiftshader in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-1213)

  - Type confusion in V8 in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1214)

  - Type confusion in CSS in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1215)

  - Use after free in DevTools in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    convienced the user to engage in direct UI interaction to potentially exploit heap corruption via a
    crafted HTML page. (Chromium security severity: High) (CVE-2023-1216)

  - Stack buffer overflow in Crash reporting in Google Chrome on Windows prior to 111.0.5563.64 allowed a
    remote attacker who had compromised the renderer process to obtain potentially sensitive information from
    process memory via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1217)

  - Use after free in WebRTC in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-1218)

  - Heap buffer overflow in Metrics in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1219)

  - Heap buffer overflow in UMA in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-1220)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 111.0.5563.64 allowed an
    attacker who convinced a user to install a malicious extension to bypass navigation restrictions via a
    crafted Chrome Extension. (Chromium security severity: Medium) (CVE-2023-1221)

  - Heap buffer overflow in Web Audio API in Google Chrome prior to 111.0.5563.64 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1222)

  - Insufficient policy enforcement in Autofill in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to leak cross-origin data via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-1223)

  - Insufficient policy enforcement in Web Payments API in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1224)

  - Insufficient policy enforcement in Intents in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1228)

  - Inappropriate implementation in Permission prompts in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-1229)

  - Inappropriate implementation in WebApp Installs in Google Chrome on Android prior to 111.0.5563.64 allowed
    an attacker who convinced a user to install a malicious WebApp to spoof the contents of the PWA installer
    via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-1230)

  - Inappropriate implementation in Autofill in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to potentially spoof the contents of the omnibox via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-1231)

  - Insufficient policy enforcement in Resource Timing in Google Chrome prior to 111.0.5563.64 allowed a
    remote attacker to obtain potentially sensitive information from API via a crafted HTML page. (Chromium
    security severity: Low) (CVE-2023-1232)

  - Insufficient policy enforcement in Resource Timing in Google Chrome prior to 111.0.5563.64 allowed an
    attacker who convinced a user to install a malicious extension to obtain potentially sensitive information
    from API via a crafted Chrome Extension. (Chromium security severity: Low) (CVE-2023-1233)

  - Inappropriate implementation in Intents in Google Chrome on Android prior to 111.0.5563.64 allowed a
    remote attacker to perform domain spoofing via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-1234)

  - Type confusion in DevTools in Google Chrome prior to 111.0.5563.64 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted UI interaction.
    (Chromium security severity: Low) (CVE-2023-1235)

  - Inappropriate implementation in Internals in Google Chrome prior to 111.0.5563.64 allowed a remote
    attacker to spoof the origin of an iframe via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-1236)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1213");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1214");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1215");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1216");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1217");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1218");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1219");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1220");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1221");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1222");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1223");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1224");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1228");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1229");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1230");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1231");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1232");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1233");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1234");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1235");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-1236");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 111.0.1661.41 / 110.0.1587.69 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1218");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-1222");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

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
  		{ 'fixed_version' : '110.0.1587.69' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '111.0.1661.41' }
	];
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
