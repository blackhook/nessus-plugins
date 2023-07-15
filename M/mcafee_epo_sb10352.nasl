##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148261);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/29");

  script_cve_id("CVE-2021-23888", "CVE-2021-23889", "CVE-2021-23890");
  script_xref(name:"MCAFEE-SB", value:"SB10352");
  script_xref(name:"IAVA", value:"2021-A-0154");

  script_name(english:"McAfee ePolicy Orchestrator Multiple Vulnerabilities (SB10352)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee ePolicy Orchestrator installed on the remote host is potentially affected by the following 
vulnerabilities:

  - An unvalidated client-side URL redirect vulnerability exists in McAfee ePolicy Orchestrator (ePO). An 
  unauthenticated, remote attacker could exploit this to cause an authenticated ePO user to load an untrusted 
  site in an ePO iframe which could steal information from the authenticated user (CVE-2021-23888).

  - A cross-site scripting (XSS) vulnerability exists in McAfee ePolicy Orchestrator (ePO) due to improper 
  validation of user-supplied input before returning it to users. An authenticated, remote attacker can exploit
  this, by convincing a user to click a specially crafted URL, to execute arbitrary script code in a user's browser
  session (CVE-2021-23889).

  - An information disclosure vulnerability exists in McAfee ePolicy Orchestrator (ePO). An unauthenticated, remote
  attacker can exploit this to disclose potentially sensitive information (CVE-2021-23890).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.10.0 Update 10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23890");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee ePO');
# HFs not detected
if (app_info.version =~ "5\.9\.1([^0-9]|$)" && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'McAfee ePO');

constraints = [{'fixed_version':'5.10.0.3488', 'fixed_display': '5.10.0 Update 10 or hotfix'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING, 
  flags:{'xss':TRUE}
);
