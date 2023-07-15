#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136968);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2020-1195",
    "CVE-2020-6465",
    "CVE-2020-6466",
    "CVE-2020-6467",
    "CVE-2020-6468",
    "CVE-2020-6469",
    "CVE-2020-6470",
    "CVE-2020-6471",
    "CVE-2020-6472",
    "CVE-2020-6473",
    "CVE-2020-6474",
    "CVE-2020-6475",
    "CVE-2020-6476",
    "CVE-2020-6478",
    "CVE-2020-6479",
    "CVE-2020-6480",
    "CVE-2020-6481",
    "CVE-2020-6482",
    "CVE-2020-6483",
    "CVE-2020-6484",
    "CVE-2020-6486",
    "CVE-2020-6487",
    "CVE-2020-6488",
    "CVE-2020-6489",
    "CVE-2020-6490"
  );
  script_xref(name:"IAVA", value:"2020-A-0228-S");

  script_name(english:"Microsoft Edge (Chromium) < 83.0.478.37 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 83.0.478.37. It is, therefore,
affected by multiple vulnerabilities:

  - A use after free in media in Microsoft Edge (Chromium) allowed a remote attacker who had
    compromised the renderer  process to potentially perform a sandbox escape via a crafted HTML page.
    (CVE-2020-6466)

  - A use after free in WebRTC in Microsoft Edge (Chromium) allowed a remote attacker to potentially
    exploit  heap corruption via a crafted HTML page. (CVE-2020-6467)

  - Type confusion in V8 in Microsoft Edge (Chromium) allowed a remote attacker to potentially exploit 
    heap corruption via a crafted HTML page. (CVE-2020-6468)

In addition, Microsoft Edge (Chromium) is also affected by several additional vulnerabilities including additional
use-after-free vulnerabilities, privilege escalations, and insufficient policy enforcements.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f0f972");
  # https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec7f076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge (Chromium) 83.0.478.37 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6474");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6471");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

constraints = [{ 'fixed_version' : '83.0.478.37' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
