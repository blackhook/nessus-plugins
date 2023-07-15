##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(144970);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/15");

  script_cve_id("CVE-2020-7317", "CVE-2020-7318");
  script_xref(name:"IAVA", value:"2020-A-0470");
  script_xref(name:"MCAFEE-SB", value:"SB10332");

  script_name(english:"McAfee ePolicy Orchestrator Multiple XSS (SB10332)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by multiple cross-site scripting vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee ePolicy Orchestrator installed on the remote host is affected by the following cross-site
scripting (XSS) vulnerabilities:

  - Cross-Site Scripting vulnerability in McAfee ePolicy Orchistrator (ePO) prior to 5.10.9 Update 9 allows
    administrators to inject arbitrary web script or HTML via parameter values for 'syncPointList' not being
    correctly sanitixed. (CVE-2020-7317)

  - Cross-Site Scripting vulnerability in McAfee ePolicy Orchestrator (ePO) prior to 5.10.9 Update 9 allows
    administrators to inject arbitrary web script or HTML via multiple parameters where the administrator's
    entries were not correctly sanitized. Note that this does not impact 5.9.x versions. (CVE-2020-7318)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.10.0 Update 9");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7318");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee ePO');
constraints = [{'min_version':'5.9', 'fixed_version':'5.10.0.3335'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{'xss':TRUE});
