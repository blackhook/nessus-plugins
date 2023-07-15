##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142456);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-16004",
    "CVE-2020-16005",
    "CVE-2020-16006",
    "CVE-2020-16007",
    "CVE-2020-16008",
    "CVE-2020-16009",
    "CVE-2020-16011"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Microsoft Edge (Chromium) < 86.0.622.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 86.0.622.63. It is, therefore, affected
by multiple vulnerabilities as referenced in the ADV200002-11-4-2020 advisory.

  - Use after free in user interface in Google Chrome prior to 86.0.4240.183 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-16004)

  - Insufficient policy enforcement in ANGLE in Google Chrome prior to 86.0.4240.183 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (CVE-2020-16005)

  - Inappropriate implementation in V8 in Google Chrome prior to 86.0.4240.183 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-16006, CVE-2020-16009)

  - Insufficient data validation in installer in Google Chrome prior to 86.0.4240.183 allowed a local attacker
    to potentially elevate privilege via a crafted filesystem. (CVE-2020-16007)

  - Stack buffer overflow in WebRTC in Google Chrome prior to 86.0.4240.183 allowed a remote attacker to
    potentially exploit stack corruption via a crafted WebRTC packet. (CVE-2020-16008)

  - Heap buffer overflow in UI in Google Chrome on Windows prior to 86.0.4240.183 allowed a remote attacker
    who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-16011)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?083510ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 86.0.622.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16011");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '86.0.622.63' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
