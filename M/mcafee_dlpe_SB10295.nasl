#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128416);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/17 14:31:05");

  script_cve_id("CVE-2019-3633", "CVE-2019-3634");
  script_xref(name:"MCAFEE-SB", value:"SB10295");
  script_xref(name:"IAVA", value:"2019-A-0308");

  script_name(english:"McAfee DLPe Agent 11.x < 11.1.210.32 / 11.2.x / 11.3.x < 11.3.2.8 Multiple Vulnerabilities (SB10295)");
  script_summary(english:"Checks the version of McAfee DLPe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote Windows host is 11.x
prior to 11.1.210.32, 11.2.x, or 11.3.x prior to 11.3.2.8. It is, therefore, affected by multiple vulnerabilities:

  - Buffer overflow in McAfee Data Loss Prevention (DLPe) for Windows 11.x prior to 11.3.2.8 allows local user to cause
    the Windows operating system to 'blue screen' via a carefully constructed message sent to DLPe which bypasses DLPe
    internal checks and results in DLPe reading unallocated memory. (CVE-2019-3633)

  - Buffer overflow in McAfee Data Loss Prevention (DLPe) for Windows 11.x prior to 11.3.2.8 allows local user to cause
    the Windows operating system to 'blue screen' via an encrypted message sent to DLPe which when decrypted results in
    DLPe reading unallocated memory. (CVE-2019-3634)");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10295");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 11.1.210.32 or 11.3.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3633");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee DLPe Agent', win_local:TRUE);

constraints = [
  { 'min_version':'11.0', 'fixed_version':'11.1.210.32' },
  { 'min_version':'11.2', 'fixed_version':'11.3.2.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
