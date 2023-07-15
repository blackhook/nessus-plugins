#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140429);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-16858",
    "CVE-2020-16859",
    "CVE-2020-16860",
    "CVE-2020-16861",
    "CVE-2020-16862",
    "CVE-2020-16864",
    "CVE-2020-16871",
    "CVE-2020-16872",
    "CVE-2020-16878"
  );
  script_xref(name:"MSKB", value:"4577501");
  script_xref(name:"MSKB", value:"4574742");
  script_xref(name:"MSFT", value:"MS20-4577501");
  script_xref(name:"MSFT", value:"MS20-4574742");
  script_xref(name:"IAVA", value:"2020-A-0407-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by multiple
vulnerabilities :

  - A cross site scripting vulnerability exists when Microsoft Dynamics 365 (on-premises) does not properly
    sanitize a specially crafted web request to an affected Dynamics server. An authenticated attacker could
    exploit the vulnerability by sending a specially crafted request to an affected Dynamics server. The
    attacker who successfully exploited the vulnerability could then perform cross-site scripting attacks on
    affected systems and run script in the security context of the current authenticated user. These attacks
    could allow the attacker to read content that the attacker is not authorized to read, use the victim's
    identity to take actions within Dynamics Server on behalf of the user, such as change permissions and
    delete content, and inject malicious content in the browser of the user. The security update addresses the
    vulnerability by helping to ensure that Dynamics Server properly sanitizes web requests. (CVE-2020-16858,
    CVE-2020-16859, CVE-2020-16861, CVE-2020-16864, CVE-2020-16871, CVE-2020-16872, CVE-2020-16878)

  - A remote code execution vulnerability exists in Microsoft Dynamics 365 (on-premises) when the server fails
    to properly sanitize web requests to an affected Dynamics server. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the context of the SQL service account. An authenticated
    attacker could exploit this vulnerability by sending a specially crafted request to a vulnerable Dynamics
    server. The security update addresses the vulnerability by correcting how Microsoft Dynamics 365
    (on-premises) validates and sanitizes user input. (CVE-2020-16860, CVE-2020-16862)");
  # https://support.microsoft.com/en-us/help/4577501/8-2-train-20092-9-2-on-premise-2-22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6eeb7c1c");
  # https://support.microsoft.com/en-us/topic/service-update-0-20-for-microsoft-dynamics-365-9-0-3d87a2b5-2292-de4d-80a1-3f2d19eb962b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cf85be3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4577501
  -KB4574742");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_detect.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Server");
  script_require_ports(139, 445);

  exit(0);
}


include('vcf.inc');

var app = 'Microsoft Dynamics 365 Server';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.2.22.14' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.20.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});


