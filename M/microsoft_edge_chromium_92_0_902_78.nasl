#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152685);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/24");

  script_cve_id(
    "CVE-2021-30598",
    "CVE-2021-30599",
    "CVE-2021-30601",
    "CVE-2021-30602",
    "CVE-2021-30603",
    "CVE-2021-30604"
  );

  script_name(english:"Microsoft Edge (Chromium) < 92.0.902.78 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 92.0.902.78. It is, therefore, affected
by multiple vulnerabilities as referenced in the August 19, 2021 advisory.

  - Use after free in ANGLE in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30604)

  - Type confusion in V8 in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to execute
    arbitrary code inside a sandbox via a crafted HTML page. (CVE-2021-30598, CVE-2021-30599)

  - Use after free in Extensions API in Google Chrome prior to 92.0.4515.159 allowed an attacker who convinced
    a user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30601)

  - Use after free in WebRTC in Google Chrome prior to 92.0.4515.159 allowed an attacker who convinced a user
    to visit a malicious website to potentially exploit heap corruption via a crafted HTML page.
    (CVE-2021-30602)

  - Data race in WebAudio in Google Chrome prior to 92.0.4515.159 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-30603)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#august-19-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97c3a98d");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30598");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30599");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30601");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30602");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30603");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-30604");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 92.0.902.78 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
var constraints = [
  { 'fixed_version' : '92.0.902.78' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
