#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172611);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id("CVE-2023-23383");
  script_xref(name:"IAVA", value:"2023-A-0148");

  script_name(english:"Azure Service Fabric Explorer Spoofing (Mar 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Azure Service Fabric installed on the remote host is affected by a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Azure Service Fabric installed on the remote host is affected by a spoofing vulnerability. A remote,
unauthenticated attacker can exploit this to compromise confidentiality.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-versions
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?477258c9");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2023-23383
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3feb191");
  # https://github.com/microsoft/service-fabric/blob/master/release_notes/Service_Fabric_ReleaseNotes_91CU2.md
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a308364");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 9.1 CU2 (9.1.1583.9590) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_service_fabric");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_service_fabric_web_detect.nbin", "microsoft_azure_service_fabric_installed.nbin");
  script_require_keys("installed_sw/Microsoft Azure Service Fabric");

  exit(0);
}

include('vcf.inc');

var appname = 'Microsoft Azure Service Fabric';

var app_info = vcf::combined_get_app_info(app:appname);

var constraints = [
    { 'fixed_version' : '9.1.1583.9590', 'fixed_display': '9.1 CU2 (9.1.1583.9590)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
