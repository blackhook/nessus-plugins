#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(165072);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2022-34700", "CVE-2022-35805");
  script_xref(name:"MSKB", value:"5017226");
  script_xref(name:"MSKB", value:"5017524");
  script_xref(name:"MSFT", value:"MS22-5017226");
  script_xref(name:"MSFT", value:"MS22-5017524");
  script_xref(name:"IAVA", value:"2022-A-0377");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (September 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update. It is, therefore, affected by the following
vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to execute unauthorized arbitrary
    commands in the context of the db_owner. (CVE-2022-34700, CVE-2022-35085)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.microsoft.com/en-gb/topic/service-update-1-12-for-microsoft-dynamics-crm-on-premises-9-1-8d9a5138-241d-4a90-832e-826cc1015326
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f252a50");
  # https://support.microsoft.com/en-gb/topic/service-update-0-40-for-microsoft-dynamics-crm-on-premises-9-0-8c3976f4-b756-4282-a0a2-d77d2ed40466
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cba5f67");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5017226
  -KB5017524");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-35805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/14");

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

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.0.40.5', 'fixed_display' : 'Update v9.0 (on-premises) Update 0.40' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.12.17', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.12' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
