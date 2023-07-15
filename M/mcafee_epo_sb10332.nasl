##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141833);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2764",
    "CVE-2020-2773",
    "CVE-2020-9484",
    "CVE-2020-13935",
    "CVE-2020-14573",
    "CVE-2020-14578",
    "CVE-2020-14579",
    "CVE-2020-14581",
    "CVE-2020-14621"
  );
  script_xref(name:"IAVA", value:"2020-A-0470");
  script_xref(name:"MCAFEE-SB", value:"SB10332");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"McAfee ePolicy Orchestrator (SB10332)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee ePolicy Orchestrator installed on the remote host is affected by multiple vulnerabilities 
including the following:

  - Multiple denial of service (DoS) vulnerabilities exist in McAfee ePolicy Orchestrator's bundled component Apache 
  Tomcat due to insufficient validation of user input. An unauthenticated, remote attacker can exploit these issues, 
  by sending specially crafted requests to an affected host, to impose DoS conditions (CVE-2020-9484, CVE-2020-13935). 

  - An authentication bypass vulnerability exists in McAfee ePolicy Orchestrator. An unauthenticated, remote attacker 
  can exploit this, to bypass authentication and access / update sensitive data (CVE-2020-14621).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.10.0 Update 9");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14621");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO');

# 5.9.1 has a hotfix - audit if it's found
if (
  app_info['version'] =~ "^5\.9\.1" &&
  !empty_or_null(app_info['Hotfixes']) &&
  app_info['Hotfixes'] =~ "(^|[^0-9])919400($|[^0-9])"
)
  audit(AUDIT_HOST_NOT, 'vulnerable as hotfix EPO-919400 has been applied');

var constraints = [{'min_version':'5.9', 'fixed_version':'5.10.0.3335'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
