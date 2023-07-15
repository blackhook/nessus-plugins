#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151020);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/29");

  script_cve_id("CVE-2021-1388");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw14141");
  script_xref(name:"CISCO-SA", value:"cisco-sa-mso-authbyp-bb5GmBQv");

  script_name(english:"Cisco ACI Multi-Site Orchestrator Application Services Engine Deployment Authentication Bypass (cisco-sa-mso-authbyp-bb5GmBQv)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, a vulnerability in an API endpoint of Cisco ACI Multi-Site Orchestrator (MSO)
installed on the Application Services Engine could allow an unauthenticated, remote attacker to bypass authentication
on an affected device. The vulnerability is due to improper token validation on a specific API endpoint. An attacker
could exploit this vulnerability by sending a crafted request to the affected API. A successful exploit could allow
the attacker to receive a token with administrator-level privileges that could be used to authenticate to the API on
affected MSO and managed Cisco Application Policy Infrastructure Controller (APIC) devices.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-mso-authbyp-bb5GmBQv
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af0345e0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw14141");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw14141");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1388");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:aci_multisite_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_aci_multisite_orchestrator_detect.nbin");
  script_require_keys("installed_sw/Cisco ACI Multi-Site Orchestrator");
  script_require_ports("Services/www", 443);

  exit(0);
}


include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Cisco ACI Multi-Site Orchestrator', port:port, webapp:TRUE);

var constraints = [
  {'min_version':'3.0', 'fixed_version':'3.0.3.13', 'fixed_display':'3.0(3m)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);