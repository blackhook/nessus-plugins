#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155174);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/18");

  script_cve_id("CVE-2021-42316");
  script_xref(name:"IAVA", value:"2021-A-0540");
  script_xref(name:"MSKB", value:"5008478");
  script_xref(name:"MSKB", value:"5008479");
  script_xref(name:"MSFT", value:"MS21-5008478");
  script_xref(name:"MSFT", value:"MS21-5008479");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (November 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update. It is, therefore, affected by the following
vulnerability:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-42316)");
  # https://support.microsoft.com/en-us/topic/service-update-1-6-for-microsoft-dynamics-crm-on-premises-9-1-8a8401c0-b8c8-4288-8c01-59d15692f2ed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98abf18c");
  # https://support.microsoft.com/en-us/topic/service-update-034-for-microsoft-dynamics-crm-on-premises-90-bd536c34-0357-4576-818f-03d80fe4f5db
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70225975");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5008478
  -KB5008479");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42316");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.34.5', 'fixed_display' : 'Update v9.0 (on-premises) Update 0.34' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.6.3', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.6' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
