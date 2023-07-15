#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170007);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/10");

  script_cve_id(
    "CVE-2023-0129",
    "CVE-2023-0130",
    "CVE-2023-0131",
    "CVE-2023-0132",
    "CVE-2023-0133",
    "CVE-2023-0134",
    "CVE-2023-0135",
    "CVE-2023-0136",
    "CVE-2023-0138",
    "CVE-2023-0139",
    "CVE-2023-0140",
    "CVE-2023-0141"
  );
  script_xref(name:"IAVA", value:"2023-A-0034-S");
  script_xref(name:"IAVA", value:"2023-A-0029-S");

  script_name(english:"Microsoft Edge (Chromium) < 109.0.1518.49 / 108.0.1462.83 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 109.0.1518.49 / 108.0.1462.83. It is,
therefore, affected by multiple vulnerabilities as referenced in the January 12, 2023 advisory.

  - Heap buffer overflow in Network Service in Google Chrome prior to 109.0.5414.74 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    HTML page and specific interactions. (Chromium security severity: High) (CVE-2023-0129)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-0130)

  - Inappropriate implementation in in iframe Sandbox in Google Chrome prior to 109.0.5414.74 allowed a remote
    attacker to bypass file download restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-0131)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to force acceptance of a permission prompt via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0132)

  - Inappropriate implementation in in Permission prompts in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to bypass main origin permission delegation via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-0133)

  - Use after free in Cart in Google Chrome prior to 109.0.5414.74 allowed an attacker who convinced a user to
    install a malicious extension to potentially exploit heap corruption via database corruption and a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-0134, CVE-2023-0135)

  - Inappropriate implementation in in Fullscreen API in Google Chrome on Android prior to 109.0.5414.74
    allowed a remote attacker to execute incorrect security UI via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-0136)

  - Heap buffer overflow in libphonenumber in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2023-0138)

  - Insufficient validation of untrusted input in Downloads in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass download restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0139)

  - Inappropriate implementation in in File System API in Google Chrome on Windows prior to 109.0.5414.74
    allowed a remote attacker to bypass file system restrictions via a crafted HTML page. (Chromium security
    severity: Low) (CVE-2023-0140)

  - Insufficient policy enforcement in CORS in Google Chrome prior to 109.0.5414.74 allowed a remote attacker
    to leak cross-origin data via a crafted HTML page. (Chromium security severity: Low) (CVE-2023-0141)

  - Microsoft Edge (Chromium-based) Remote Code Execution Vulnerability. (CVE-2023-21775)

  - Microsoft Edge (Chromium-based) Elevation of Privilege Vulnerability. This CVE ID is unique from
    CVE-2023-21795. (CVE-2023-21796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?245dfb65");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0129");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0130");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0131");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0132");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0133");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0134");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0135");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0136");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0138");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0139");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0140");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-0141");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21775");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21796");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 109.0.1518.49 / 108.0.1462.83 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0135");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (extended) {
	constraints = [
  		{ 'fixed_version' : '108.0.1462.83' }
	];
} else {
	constraints = [
  		{ 'fixed_version' : '109.0.1518.49' }
	];
};
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
