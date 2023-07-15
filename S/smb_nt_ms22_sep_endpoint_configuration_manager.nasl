#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165336);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2022-37972");
  script_xref(name:"MSKB", value:"15498768");
  script_xref(name:"MSFT", value:"MS22-15498768");
  script_xref(name:"IAVA", value:"2022-A-0385");

  script_name(english:"Microsoft Endpoint Configuration Manager Spoofing (KB15498768)");

  script_set_attribute(attribute:"synopsis", value:
"A system management application installed on the remote host is affected by a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Endpoint Configuration Manager application installed on the remote host is missing a security hotfix
documented in KB15498768. It is, therefore, affected by a spoofing vulnerability. Under some conditions, clients will
fallback to NTLM authentication even if NTLM authentication is disabled.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-gb/mem/configmgr/hotfix/2207/15498768
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0edabdd");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-37972
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba3f40ec");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch according to KB15498768.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37972");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:endpoint_configuration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_configuration_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_systems_management_server_installed.nasl");
  script_require_ports("installed_sw/Microsoft Endpoint Configuration Manager");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::endpoint_cm::get_app_info();

var constraints = [
  # Min Version for first time product was known as Endpoint Configuration Manager
  {'min_version': '5.0.8913', 'fixed_version': '5.0.9049.1045', 'fixed_display': 'See vendor advisory', 'file': 'ccm.dll'},
  {'min_version': '5.0.9058', 'fixed_version': '5.0.9058.1050', 'fixed_display': 'See vendor advisory', 'file': 'ccm.dll'},
  {'min_version': '5.0.9068', 'fixed_version': '5.0.9068.1031', 'fixed_display': 'See vendor advisory', 'file': 'ccm.dll'},
  {'min_version': '5.0.9078', 'fixed_version': '5.0.9078.1027', 'fixed_display': 'See vendor advisory', 'file': 'ccm.dll'},
  {'min_version': '5.0.9088', 'fixed_version': '5.0.9088.1012', 'fixed_display': 'See vendor advisory', 'file': 'ccm.dll'}

];

vcf::microsoft::endpoint_cm::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
