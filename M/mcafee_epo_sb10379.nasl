#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159332);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2022-0842",
    "CVE-2022-0857",
    "CVE-2022-0858",
    "CVE-2022-0859",
    "CVE-2022-0861",
    "CVE-2022-0862"
  );
  script_xref(name:"MCAFEE-SB", value:"SB10379");
  script_xref(name:"IAVA", value:"2022-A-0125-S");

  script_name(english:"McAfee ePolicy Orchestrator Multiple Vulnerabilities (SB10379)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee ePolicy Orchestrator installed on the remote host is affected by multiple vulnerabilities,
including the following:

  - McAfee Enterprise ePolicy Orchestrator (ePO) prior to 5.10 Update 13 allows a local attacker to point an
    ePO server to an arbitrary SQL server during the restoration of the ePO server. To achieve this the
    attacker would have to be logged onto the server hosting the ePO server (restricted to administrators) and
    to know the SQL server password. (CVE-2022-0859)

  - A blind SQL injection vulnerability in McAfee Enterprise ePolicy Orchestrator (ePO) prior to 5.10 Update
    13 allows a remote authenticated attacker to potentially obtain information from the ePO database. The
    data obtained is dependent on the privileges the attacker has and to obtain sensitive data the attacker
    would require administrator privileges. (CVE-2022-0842)

  - A reflected cross-site scripting (XSS) vulnerability in McAfee Enterprise ePolicy Orchestrator (ePO) prior
    to 5.10 Update 13 allows a remote attacker to potentially obtain access to an ePO administrator's session
    by convincing the attacker to click on a carefully crafted link. This would lead to limited access to
    sensitive information and limited ability to alter some information in ePO due to the area of the User
    Interface the vulnerability is present in. (CVE-2022-0857)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10379");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.10.0 Update 13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0861");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0859");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/30");

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

# 5.10.0.3805 is the highest version seen in Superset. To be validated against the target in SRP-507.
# 5.10.0.3790 seen with grep.
var constraints = [{'fixed_version' : '5.10.0.3790' , 'fixed_display': '5.10.0 Update 13'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE, 'sqli':TRUE}
);
