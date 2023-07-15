#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159732);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/19");

  script_cve_id("CVE-2022-23259");
  script_xref(name:"MSKB", value:"5012731");
  script_xref(name:"MSKB", value:"5012732");
  script_xref(name:"MSFT", value:"MS22-5012731");
  script_xref(name:"MSFT", value:"MS22-5012732");
  script_xref(name:"IAVA", value:"2022-A-0146-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (April 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update. It is, therefore, affected by a remote code 
execution vulnerability in its database component. An authenticated, remote attacker can exploit this to bypass 
authentication and execute arbitrary commands. 

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://support.microsoft.com/en-gb/topic/service-update-1-9-for-microsoft-dynamics-crm-on-premises-9-1-ac199135-707b-4a32-bc02-08250f03793d
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa46bd3c");
  # https://support.microsoft.com/en-gb/topic/service-update-037-for-microsoft-dynamics-crm-on-premises-9-0-33af16f3-6578-460a-8242-f75b68c3e5c8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03aa5a28");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5012731
  -KB5012732");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Dynamics 365 Server', win_local:TRUE);

var constraints = [
  {'min_version': '9.0', 'fixed_version': '9.0.37.2', 'fixed_display': 'Update v9.0 (on-premises) Update 0.37'}, 
  {'min_version': '9.1', 'fixed_version': '9.1.9.8', 'fixed_display': 'Update v9.1 (on-premises) Update 1.9'} 
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
