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
  script_id(136513);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id("CVE-2020-1063", "CVE-2020-1328");
  script_xref(name:"MSKB", value:"4551998");
  script_xref(name:"MSKB", value:"4552002");
  script_xref(name:"MSFT", value:"MS20-4551998");
  script_xref(name:"MSFT", value:"MS20-4552002");
  script_xref(name:"IAVA", value:"2020-A-0212");
  script_xref(name:"IAVA", value:"2020-A-0250");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (May 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing a security update. It is, therefore, affected by the following
vulnerabilities : 

  - A cross-site scripting vulnerability exists when Microsoft Dynamics 365 (on-premises) does not properly
    sanitize a specially crafted web request to an affected Dynamics server. An authenticated attacker could
    exploit the vulnerability by sending a specially crafted request to an affected Dynamics server. The
    attacker who successfully exploited the vulnerability could then perform cross-site scripting attacks on
    affected systems and run script in the security context of the current authenticated user. These attacks
    could allow the attacker to read content that the attacker is not authorized to read, use the victim's
    identity to take actions within Dynamics Server on behalf of the user, such as change permissions and
    delete content, and inject malicious content in the browser of the user. The security update addresses the
    vulnerability by helping to ensure that Dynamics Server properly sanitizes web requests. (CVE-2020-1063,
    CVE-2020-1328)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  # https://support.microsoft.com/en-us/help/4551998/microsoft-dynamics-365-on-premises-update-2-18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de603e48");
  # https://support.microsoft.com/en-us/help/4552002/service-update-0-16-for-microsoft-dynamics-365-9-0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e42a9f8");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4551998
  -KB4552002");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1063");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

app = 'Microsoft Dynamics 365 Server';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2.18.16' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.16.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
