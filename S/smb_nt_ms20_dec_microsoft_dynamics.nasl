##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(143608);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/14");

  script_cve_id("CVE-2020-17147");
  script_xref(name:"MSKB", value:"4595459");
  script_xref(name:"MSKB", value:"4595462");
  script_xref(name:"MSFT", value:"MS20-4595459");
  script_xref(name:"MSFT", value:"MS20-4595462");
  script_xref(name:"IAVA", value:"2020-A-0552");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (December 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update. It is, therefore, affected by a cross-site 
scripting (XSS) vulnerability due to improper validation of user-supplied input before returning it to users. An 
attacker can exploit this by convincing a user to click a specially crafted URL, to execute arbitrary script code in a 
user's browser session.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4595459");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4595462");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4595459
  -KB4595462");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Microsoft Dynamics 365 Server', win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2.25.16' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.23.7' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{xss:TRUE}
);
