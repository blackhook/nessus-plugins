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
  script_id(156771);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2022-21891", "CVE-2022-21932");
  script_xref(name:"IAVA", value:"2022-A-0010");
  script_xref(name:"MSKB", value:"5010574");
  script_xref(name:"MSKB", value:"5010575");
  script_xref(name:"MSFT", value:"MS21-5010574");
  script_xref(name:"MSFT", value:"MS21-5010575");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (January 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update. It is, therefore, affected by the following
vulnerability:

  - Spoofing Vulnerability (CVE-2022-21891)

  - Cross-site Scripting Vulnerabilities (CVE-2022-21932)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://support.microsoft.com/en-us/topic/service-update-035-for-microsoft-dynamics-crm-on-premises-90-ba3abb84-02e6-4ebf-a232-1e4feeeb7f1b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01ea506a");
  # https://support.microsoft.com/en-gb/topic/service-update-1-7-for-microsoft-dynamics-crm-on-premises-9-1-f2496aae-72bc-4dd4-987f-448bce5dd1b9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?102b1180");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5010574
  -KB5010575");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21891");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-21932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/17");

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
  { 'min_version' : '9.0', 'fixed_version' : '9.0.35.12', 'fixed_display' : 'Update v9.0 (on-premises) Update 0.35' }, 
  { 'min_version' : '9.1', 'fixed_version' : '9.1.7.5', 'fixed_display' : 'Update v9.1 (on-premises) Update 1.7' } 
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
