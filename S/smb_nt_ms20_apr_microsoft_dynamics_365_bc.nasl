#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136425);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

  script_cve_id("CVE-2020-1018", "CVE-2020-1022");
  script_xref(name:"MSKB", value:"4549676");
  script_xref(name:"MSKB", value:"4549677");
  script_xref(name:"MSKB", value:"4549678");
  script_xref(name:"MSFT", value:"MS20-4549676");
  script_xref(name:"MSFT", value:"MS20-4549677");
  script_xref(name:"MSFT", value:"MS20-4549678");
  script_xref(name:"IAVA", value:"2020-A-0160-S");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (Apr 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update. It is, therefore, affected by a
the following vulnerabilities :

  - An information disclosure vulnerability exists in Business Central due to the application not properly
    hiding the value of a masked field when showing the records as a chart page. An unauthenticated, remote
    attacker can exploit this to disclose potentially sensitive information. (CVE-2020-1018)

  - A remote code execution vulnerability exists in Business Central due to an unspecified reason. An
    authenticated, remote attacker can exploit this by convincing a user to connect to a malicious Dynamics
    Business Central client to execute arbitrary commands. (CVE-2020-1022)

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4549676");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4549677");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4549678");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to CU18 for the October 2018 release, CU11 for the April 2019 release,
15.5 for 2019 Release Wave 2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1022");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics 365 Business Central Server';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '13.0', 'fixed_version' : '13.0.41879.0' }, # 2019 October Update
  { 'min_version' : '14.0', 'fixed_version' : '14.0.41862.0' }, # 2019 Spring Update
  { 'min_version' : '15.0', 'fixed_version' : '15.0.41893.0' }  # 2019 Release Wave 2
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
