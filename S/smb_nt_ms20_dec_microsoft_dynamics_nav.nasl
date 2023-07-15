##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147956);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/24");

  script_cve_id("CVE-2020-17133");
  script_xref(name:"MSKB", value:"4583556");
  script_xref(name:"MSFT", value:"MS20-4583556");

  script_name(english:"Security Updates for Microsoft Dynamics NAV (Dec 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Dynamics NAV install is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Dynamics NAV install is missing a security update. It is, therefore, affected by an information
disclosure vulnerability in the Document Service table due to the Password field not being masked. An authenticated,
remote attacker can exploit this, by inspecting as a system user, to reveal passwords.

Note that Nessus has not attempted to exploit this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4583556");
  script_set_attribute(attribute:"solution", value:
"Install the approprate update package from KB4583556.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:dynamics_nav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_dynamics_nav_server_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Dynamics NAV Server");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

app = 'Microsoft Dynamics NAV Server';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '7.1', 'fixed_version' : '7.1.51940.0' }, # 2013 R2
  { 'min_version' : '8.0', 'fixed_version' : '8.0.51958.0' }  # 2015
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
