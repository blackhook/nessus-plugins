#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166139);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-3338", "CVE-2022-3339");
  script_xref(name:"MCAFEE-SB", value:"SB10387");
  script_xref(name:"IAVA", value:"2022-A-0420");

  script_name(english:"McAfee ePolicy Orchestrator Multiple Vulnerabilities (SB10387)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee ePolicy Orchestrator installed on the remote host is affected by multiple vulnerabilities,
including the following:

  - An External XML entity (XXE) vulnerability in ePO prior to 5.10 Update 14 can lead to an unauthenticated 
    remote attacker to potentially trigger a Server Side Request Forgery attack. This can be exploited by 
    mimicking the Agent Handler call to ePO and passing the carefully constructed XML file through the API. 
    (CVE-2022-3338)

  - A reflected cross-site scripting (XSS) vulnerability in ePO prior to 5.10 Update 14 allows a remote 
    unauthenticated attacker to potentially obtain access to an ePO administrator's session by convincing the 
    authenticated ePO administrator to click on a carefully crafted link. This would lead to limited access 
    to sensitive information and limited ability to alter some information in ePO. (CVE-2022-3339)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10387");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.10.0 Update 14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO');

# Found by grepping for version from download package (Ex. grep -ir 5.10.0.3)
var constraints = [{'fixed_version' : '5.10.0.3923' , 'fixed_display' : '5.10.0 Update 14'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
