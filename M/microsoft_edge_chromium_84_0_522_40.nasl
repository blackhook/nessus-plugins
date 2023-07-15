#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139034);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-1341",
    "CVE-2020-6510",
    "CVE-2020-6511",
    "CVE-2020-6512",
    "CVE-2020-6513",
    "CVE-2020-6514",
    "CVE-2020-6515",
    "CVE-2020-6516",
    "CVE-2020-6517",
    "CVE-2020-6518",
    "CVE-2020-6519",
    "CVE-2020-6520",
    "CVE-2020-6522",
    "CVE-2020-6523",
    "CVE-2020-6524",
    "CVE-2020-6525",
    "CVE-2020-6526",
    "CVE-2020-6527",
    "CVE-2020-6528",
    "CVE-2020-6529",
    "CVE-2020-6530",
    "CVE-2020-6531",
    "CVE-2020-6533",
    "CVE-2020-6534",
    "CVE-2020-6535",
    "CVE-2020-6536"
  );
  script_xref(name:"IAVA", value:"2020-A-0302-S");

  script_name(english:"Microsoft Edge (Chromium) < 84.0.522.40 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 84.0.522.40. It is,
therefore, affected by multiple vulnerabilities :

  - Heap-based buffer overflow in PDFium allowed a remote attacker to potentially exploit heap corruption via a
    crafted PDF file. (CVE-2020-6513)

  - Use after free in tab strip allowed a remote attacker to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2020-6515)

  - Out of bounds write in Skia allowed a remote attacker to potentially exploit heap corruption via a crafted
    HTML page. (CVE-2020-6523)

In addition, Microsoft Edge (Chromium) is also affected by several additional vulnerabilities including additional
use-after-free vulnerabilities, multiple heap-based buffer overflow conditions, privilege escalation, type confusion,
and insufficient policy enforcements.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f0f972");
  # https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec7f076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge (Chromium) 84.0.522.40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-6522");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

constraints = [{ 'fixed_version' : '84.0.522.40' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
