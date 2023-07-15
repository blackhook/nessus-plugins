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
  script_id(154172);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/21");

  script_cve_id("CVE-2021-41353", "CVE-2021-41354");
  script_xref(name:"MSKB", value:"4618795");
  script_xref(name:"MSKB", value:"4618810");
  script_xref(name:"MSFT", value:"MS21-4618795");
  script_xref(name:"MSFT", value:"MS21-4618810");
  script_xref(name:"IAVA", value:"2021-A-0464");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (Oct 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) installation on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities: 

  - A spoofing vulnerability (CVE-2021-41353)

  - A cross-site scripting vulnerability (CVE-2021-41354)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  # https://support.microsoft.com/en-us/topic/service-update-0-31-for-microsoft-dynamics-crm-on-premises-9-0-5bb7ff5b-8fbd-465c-8590-6e4522289913
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4aaa913");
  # https://support.microsoft.com/en-gb/topic/service-update-1-4-for-microsoft-dynamics-crm-on-premises-9-1-717b1982-3824-4bb7-9356-1511848ed0f4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4163d401");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -4618795
  -4618810");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
  { 'min_version' : '9.0', 'fixed_version' : '9.0.31.7' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.4.31' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
