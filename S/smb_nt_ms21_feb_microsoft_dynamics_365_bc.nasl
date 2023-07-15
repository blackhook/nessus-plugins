##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146418);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/04");

  script_cve_id("CVE-2021-1724");
  script_xref(name:"MSKB", value:"4602915");
  script_xref(name:"MSFT", value:"MS21-4602915");

  script_name(english:"Security Updates for Microsoft Dynamics 365 Business Central (Feb 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics 365 Business Central install is missing a security update. It is, therefore, affected by a
cross site scripting (XSS) vulnerability due to improper validation of user-supplied input. An authenticated attacker
can exploit this, by entering specially crafted URLs in the Links and Notes feature, in order to disclose information.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4602915");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Dynamics 365 Business Central to CU21 for the Spring 2019 release, 16.10 for 2020 Release Wave 1, 17.4 for 2020 Release Wave 2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1724");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_365");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_365_business_central_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics 365 Business Central Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics 365 Business Central Server';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '14.0', 'fixed_version' : '14.0.46351.0', 'fixed_display' : 'CU 21 for Microsoft Dynamics 365 Business Central Spring 2019' },
  { 'min_version' : '16.0', 'fixed_version' : '16.0.21469.0', 'fixed_display' : 'Update 16.10 for Microsoft Dynamics 365 Business Central 2020 Release Wave 1' },
  { 'min_version' : '17.0', 'fixed_version' : '17.0.21516.0', 'fixed_display' : 'Update 17.4 for Microsoft Dynamics 365 Business Central 2020 Release Wave 2' }

];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
