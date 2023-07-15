#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154721);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-31834", "CVE-2021-31835");
  script_xref(name:"MCAFEE-SB", value:"SB10366");
  script_xref(name:"IAVA", value:"2021-A-0499-S");

  script_name(english:"McAfee ePolicy Orchestrator Multiple Vulnerabilities (SB10366)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee ePolicy Orchestrator installed on the remote host is affected by the following vulnerabilities:

  - Stored Cross-Site Scripting vulnerability in McAfee ePolicy Orchestrator (ePO) prior to 5.10 Update 11
    allows ePO administrators to inject arbitrary web script or HTML via multiple parameters where the
    administrator's entries were not correctly sanitized. (CVE-2021-31834)

  - Cross-Site Scripting vulnerability in McAfee ePolicy Orchestrator (ePO) prior to 5.10 Update 11 allows ePO
    administrators to inject arbitrary web script or HTML via a specific parameter where the administrator's
    entries were not correctly sanitized. (CVE-2021-31835)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10366");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.10.0 Update 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31835");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee ePO');

var constraints = [{'fixed_version' : '5.10.0.3669' , 'fixed_display': '5.10.0 Update 11'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
