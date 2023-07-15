#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139061);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id("CVE-2020-6464", "CVE-2020-6831");

  script_name(english:"Microsoft Edge (Chromium) < 81.0.416.72 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 81.0.416.72. It is, therefore,
affected by multiple vulnerabilities:

  - A buffer overflow could occur when parsing and validating SCTP chunks in WebRTC. This could have led to 
    memory corruption and a potentially exploitable crash. (CVE-2020-6831)

  - Type confusion in Blink in Microsoft Edge (Chromium) allowed a remote attacker to potentially 
    exploit heap corruption via a crafted HTML page. (CVE-2020-6464)");
  # https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec7f076");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f0f972");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge (Chromium) 81.0.416.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6831");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

constraints = [{ 'fixed_version' : '81.0.416.72' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

