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
  script_id(142692);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id(
    "CVE-2020-17005",
    "CVE-2020-17006",
    "CVE-2020-17018",
    "CVE-2020-17021"
  );
  script_xref(name:"MSKB", value:"4577009");
  script_xref(name:"MSKB", value:"4584611");
  script_xref(name:"MSKB", value:"4584612");
  script_xref(name:"MSFT", value:"MS20-4577009");
  script_xref(name:"MSFT", value:"MS20-4584611");
  script_xref(name:"MSFT", value:"MS20-4584612");
  script_xref(name:"IAVA", value:"2020-A-0520-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 (on-premises) (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 (on-premises) is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 (on-premises) is missing security updates. It is, therefore, affected by multiple cross-site
scripting (XSS) vulnerabilities. An authenticated, remote attacker could exploit this, by sending a specially crafted
request to an affected Dynamics server. The attacker who successfully exploited the vulnerability could then perform
cross-site scripting attacks on affected systems and run script in the security context of the current authenticated
user.");
  # https://support.microsoft.com/en-us/help/4584611/9-0-train-20112-11-2-on-premise-0-22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df6522ea");
  # https://support.microsoft.com/en-us/help/4584612/8-2-train-20112-11-2-on-premise-2-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba8db6b1");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4577009");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4577009
  -KB4584611
  -KB4584612");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17021");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

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

app = 'Microsoft Dynamics 365 Server';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.0.3.155' },
  { 'min_version' : '8.0', 'fixed_version' : '8.2.24.14' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.22.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
