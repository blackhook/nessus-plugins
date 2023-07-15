#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171544);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id(
    "CVE-2023-21570",
    "CVE-2023-21571",
    "CVE-2023-21572",
    "CVE-2023-21573",
    "CVE-2023-21807",
    "CVE-2023-24879",
    "CVE-2023-24891",
    "CVE-2023-24919",
    "CVE-2023-24920",
    "CVE-2023-24921",
    "CVE-2023-24922"
  );
  script_xref(name:"MSKB", value:"5023505");
  script_xref(name:"MSKB", value:"5023506");
  script_xref(name:"MSFT", value:"MS23-5023505");
  script_xref(name:"MSFT", value:"MS23-5023506");
  script_xref(name:"IAVA", value:"2023-A-0089-S");
  script_xref(name:"IAVA", value:"2023-A-0134-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by multiple session
spoofing vulnerabilities. An attacker can exploit these to perform actions with the privileges of another user

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5023505");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5023506");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5023505
  -KB5023506");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24922");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.45.11', 'fixed_display' : 'Update v9.0 (on-premises) Update 0.45' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.16.20', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.16' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{'xss':TRUE}
);
