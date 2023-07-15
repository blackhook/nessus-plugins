##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146207);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/12");

  script_cve_id(
    "CVE-2021-21142",
    "CVE-2021-21143",
    "CVE-2021-21144",
    "CVE-2021-21145",
    "CVE-2021-21146",
    "CVE-2021-21147",
    "CVE-2021-24113"
  );

  script_name(english:"Microsoft Edge (Chromium) < 88.0.705.62 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 88.0.705.62. It is, therefore, affected
by multiple vulnerabilities as referenced in the February 4, 2021 advisory.

  - Use after free in Payments in Google Chrome on Mac prior to 88.0.4324.146 allowed a remote attacker to
    potentially perform a sandbox escape via a crafted HTML page. (CVE-2021-21142)

  - Heap buffer overflow in Extensions in Google Chrome prior to 88.0.4324.146 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-21143)

  - Heap buffer overflow in Tab Groups in Google Chrome prior to 88.0.4324.146 allowed an attacker who
    convinced a user to install a malicious extension to potentially exploit heap corruption via a crafted
    Chrome Extension. (CVE-2021-21144)

  - Use after free in Fonts in Google Chrome prior to 88.0.4324.146 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (CVE-2021-21145)

  - Use after free in Navigation in Google Chrome prior to 88.0.4324.146 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2021-21146)

  - Inappropriate implementation in Skia in Google Chrome prior to 88.0.4324.146 allowed a local attacker to
    spoof the contents of the Omnibox (URL bar) via a crafted HTML page. (CVE-2021-21147)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#february-4-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6e795b0");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21142");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21143");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21144");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21145");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21146");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-21147");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24113");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 88.0.705.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/10");

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
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '88.0.705.62' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
