#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153474);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id(
    "CVE-2021-38645",
    "CVE-2021-38647",
    "CVE-2021-38648",
    "CVE-2021-38649"
  );
  script_xref(name:"IAVA", value:"2021-A-0433");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0044");

  script_name(english:"Microsoft Open Management Infrastructure < 1.6.8.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Azure Open Management Infrastructure server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Azure Open Management Infrastructure installed on the remote host is prior to 1.6.8.1. It is, therefore,
affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in the OMI agent. An unauthenticated, remote attacker can exploit 
    this to bypass authentication and execute arbitrary commands with root privileges. (CVE-2021-38647)
    
  - Multiple privilege escalation vulnerabilities exists in the OMI agent. An unauthenticated, remote attacker can
    exploit this, to gain privileged access to the system. (CVE-2021-38645, CVE-2021-38648, CVE-2021-38649)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/Microsoft/omi/releases/");
  script_set_attribute(attribute:"see_also", value:"https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Azure Open Management Infrastructure version 1.6.8.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38647");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft OMI Management Interface Authentication Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:open_management_infrastructure");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_omi_nix_installed.nbin");
  script_require_keys("installed_sw/omi");

  exit(0);
}

include('vcf.inc');

vcf::add_separator('-'); # used in parsing version for vcf
app_info = vcf::combined_get_app_info(app:'omi');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '1.6.8.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
