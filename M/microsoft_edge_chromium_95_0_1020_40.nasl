#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154738);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-37997",
    "CVE-2021-37998",
    "CVE-2021-37999",
    "CVE-2021-38000",
    "CVE-2021-38001",
    "CVE-2021-38002",
    "CVE-2021-38003"
  );
  script_xref(name:"IAVA", value:"2021-A-0522-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Microsoft Edge (Chromium) < 95.0.1020.40 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 95.0.1020.40. It is, therefore, affected
by multiple vulnerabilities as referenced in the October 29, 2021 advisory.

  - Inappropriate implementation in V8 in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-38003)

  - Use after free in Sign-In in Google Chrome prior to 95.0.4638.69 allowed a remote attacker who convinced a
    user to sign into Chrome to potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37997)

  - Use after free in Garbage Collection in Google Chrome prior to 95.0.4638.69 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2021-37998)

  - Insufficient data validation in New Tab Page in Google Chrome prior to 95.0.4638.69 allowed a remote
    attacker to inject arbitrary scripts or HTML in a new browser tab via a crafted HTML page.
    (CVE-2021-37999)

  - Insufficient validation of untrusted input in Intents in Google Chrome on Android prior to 95.0.4638.69
    allowed a remote attacker to arbitrarily browser to a malicious URL via a crafted HTML page.
    (CVE-2021-38000)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#october-29-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd5c7f7f");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37997");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37998");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-37999");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38000");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38001");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38002");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-38003");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 95.0.1020.40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38003");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-38002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '95.0.1020.40' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
