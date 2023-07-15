#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(165705);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2022-41040", "CVE-2022-41082");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/21");
  script_xref(name:"IAVA", value:"2022-A-0474-S");
  script_xref(name:"CEA-ID", value:"CEA-2022-0031");

  script_name(english:"Microsoft Exchange Server October 2022 Zero-day Vulnerabilities (ProxyNotShell)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is potentially affected by multiple zero-day vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is potentially affected by multiple zero-day
vulnerabilities, dubbed ProxyNotShell:

  - An unspecified authenticated server-side request forgery (SSRF) vulnerability. (CVE-2022-41040)

  - An unspecified authenticated remote code execution (RCE) vulnerability when PowerShell is accessible to the
    attacker. (CVE-2022-41082)

Please refer to Microsoft for guidance on mitigations for these vulnerabilities.");
  # https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57fc3035");
  # https://www.tenable.com/blog/cve-2022-41040-and-cve-2022-41082-proxyshell-variant-exploited-in-the-wild
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7cacb5");
  script_set_attribute(attribute:"see_also", value:"https://community.tenable.com/s/feed/0D53a00008oIvkYCAS");
  script_set_attribute(attribute:"solution", value:
"Contact Microsoft for patching guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange ProxyNotShell RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints =
[
  {
    'product' : '2013',
    'cu': 23,
    'unsupported_cu': 22,
    'fixed_version': '15.0.1497.42.1',
    'fixed_display': 'Contact Microsoft for patching guidance.'
  },
  {
    'product' : '2016',
    'cu': 22,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2375.32.1',
    'fixed_display': 'Contact Microsoft for patching guidance.'
  },
  {
    'product': '2016',
    'cu': 23,
    'unsupported_cu': 21,
    'fixed_version': '15.1.2507.13.1',
    'fixed_display': 'Contact Microsoft for patching guidance.'
  },
  {
    'product' : '2019',
    'cu': 11,
    'unsupported_cu': 10,
    'fixed_version': '15.2.986.36',
    'fixed_display': 'Contact Microsoft for patching guidance.'
  },
  {
    'product' : '2019',
    'cu': 12,
    'unsupported_cu': 10,
    'fixed_version': '15.2.1118.15.1',
    'fixed_display': 'Contact Microsoft for patching guidance.'
  }
];

vcf::microsoft::exchange::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
