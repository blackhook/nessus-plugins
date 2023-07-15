#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171335);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/13");

  script_cve_id(
    "CVE-2021-38005",
    "CVE-2021-38006",
    "CVE-2021-38007",
    "CVE-2021-38008",
    "CVE-2021-38009",
    "CVE-2021-38010",
    "CVE-2021-38011",
    "CVE-2021-38012",
    "CVE-2021-38013",
    "CVE-2021-38014",
    "CVE-2021-38015",
    "CVE-2021-38016",
    "CVE-2021-38017",
    "CVE-2021-38018",
    "CVE-2021-38019",
    "CVE-2021-38020",
    "CVE-2021-38021",
    "CVE-2021-38022",
    "CVE-2021-42308",
    "CVE-2021-43221"
  );

  script_name(english:"Microsoft Edge (Chromium) < 96.0.1054.29 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 96.0.1054.29. It is, therefore, affected
by multiple vulnerabilities as referenced in the November 19, 2021 advisory.

  - Use after free in loader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38005)

  - Use after free in storage foundation in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38006, CVE-2021-38011)

  - Type confusion in V8 in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38007, CVE-2021-38012)

  - Use after free in media in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-38008)

  - Inappropriate implementation in cache in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    leak cross-origin data via a crafted HTML page. (CVE-2021-38009)

  - Inappropriate implementation in service workers in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker who had compromised the renderer process to bypass site isolation via a crafted HTML page.
    (CVE-2021-38010)

  - Heap buffer overflow in fingerprint recognition in Google Chrome on ChromeOS prior to 96.0.4664.45 allowed
    a remote attacker who had compromised a WebUI renderer process to potentially perform a sandbox escape via
    a crafted HTML page. (CVE-2021-38013)

  - Out of bounds write in Swiftshader in Google Chrome prior to 96.0.4664.45 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38014)

  - Inappropriate implementation in input in Google Chrome prior to 96.0.4664.45 allowed an attacker who
    convinced a user to install a malicious extension to bypass navigation restrictions via a crafted Chrome
    Extension. (CVE-2021-38015)

  - Insufficient policy enforcement in background fetch in Google Chrome prior to 96.0.4664.45 allowed a
    remote attacker to bypass same origin policy via a crafted HTML page. (CVE-2021-38016)

  - Insufficient policy enforcement in iframe sandbox in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38017)

  - Inappropriate implementation in navigation in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to perform domain spoofing via a crafted HTML page. (CVE-2021-38018)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 96.0.4664.45 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (CVE-2021-38019)

  - Insufficient policy enforcement in contacts picker in Google Chrome on Android prior to 96.0.4664.45
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (CVE-2021-38020)

  - Inappropriate implementation in referrer in Google Chrome prior to 96.0.4664.45 allowed a remote attacker
    to bypass navigation restrictions via a crafted HTML page. (CVE-2021-38021)

  - Inappropriate implementation in WebAuthentication in Google Chrome prior to 96.0.4664.45 allowed a remote
    attacker to leak cross-origin data via a crafted HTML page. (CVE-2021-38022)

  - Microsoft Edge (Chromium-based) Spoofing Vulnerability (CVE-2021-42308)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability (CVE-2021-43221)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38005");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38006");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38007");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38008");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38009");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38010");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38011");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38012");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38013");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38014");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38015");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38016");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38017");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38018");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38019");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38020");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38021");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38022");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42308");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-43221");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 96.0.1054.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38017");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38013");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

var extended = FALSE;
if (app_info['Channel'] == 'extended') extended = TRUE;

var constraints;
if (!extended) {
	constraints = [
  		{ 'fixed_version' : '96.0.1054.29' }
	];
} else {
	audit(AUDIT_INST_VER_NOT_VULN, 'Microsoft Edge (Chromium)');
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
