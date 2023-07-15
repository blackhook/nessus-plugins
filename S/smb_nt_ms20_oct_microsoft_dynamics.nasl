#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(141429);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16956", "CVE-2020-16978");
  script_xref(name:"MSKB", value:"4578106");
  script_xref(name:"MSKB", value:"4578105");
  script_xref(name:"MSFT", value:"MS20-4578106");
  script_xref(name:"MSFT", value:"MS20-4578105");
  script_xref(name:"IAVA", value:"2020-A-0463-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security security updates. It is, therefore, affected by a
cross-site scripting vulnerability due to not properly sanitizing specially crafted web requests. An authenticated
attacker could exploit the vulnerability by sending a specially crafted request to an affected Dynamics server. The
attacker who successfully exploited the vulnerability could then perform cross-site scripting attacks on affected
systems and run script in the security context of the current authenticated user. These attacks could allow the attacker
to read content that the attacker is not authorized to read, use the victim's identity to take actions within Dynamics
Server on behalf of the user, such as change permissions and delete content, and inject malicious content in the browser
of the user. The security update addresses the vulnerability by helping to ensure that Dynamics Server properly
sanitizes web requests.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578106");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4578105");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4578106
  -KB4578105");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16956");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics 365 Server';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2.23.16' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.21.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});


