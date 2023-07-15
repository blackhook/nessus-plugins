##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145793);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2021-1283");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07941");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07942");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07945");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv07947");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dcnm-info-disc-QCSJB6YG");
  script_xref(name:"IAVA", value:"2021-A-0048");

  script_name(english:"Cisco Data Center Network Manager Information Disclosure (cisco-sa-dcnm-info-disc-QCSJB6YG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Data Center Network Manager (DCNM) is affected by a vulnerability due to
an improperly masked sensitive information that is written to a system log file. An authenticated, local attacker with 
valid user credentials can exploit this, by authenticating to an affected device and inspecting a specific system log 
file to view sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dcnm-info-disc-QCSJB6YG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53480e0a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv07941, CSCvv07942, CSCvv07945, CSCvv07947");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1283");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(789);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl", "cisco_prime_dcnm_web_detect.nasl");
  script_require_ports("installed_sw/Cisco Prime DCNM", "installed_sw/cisco_dcnm_web");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_dcnm_web::get_app_info();
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '11.5.1.0', 'fixed_display' : '11.5(1)' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);