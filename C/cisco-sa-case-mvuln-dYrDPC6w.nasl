#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151019);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_cve_id("CVE-2021-1393", "CVE-2021-1396");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw14124");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw55819");
  script_xref(name:"CISCO-SA", value:"cisco-sa-case-mvuln-dYrDPC6w");

  script_name(english:"Cisco Application Services Engine Unauthorized Access Vulnerabilities (cisco-sa-case-mvuln-dYrDPC6w)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Services Engine affected by multiple Unauthorized Access
Vulnerabilities.

  - A vulnerability in Cisco Application Services Engine could allow an unauthenticated, remote attacker to
    access a privileged service on an affected device.  The vulnerability is due to insufficient access
    controls for a service running in the Data Network. An attacker could exploit this vulnerability by
    sending crafted TCP requests to a specific service. A successful exploit could allow the attacker to
    have privileged access to run containers or invoke host-level operations. (CVE-2021-1393)

  - A vulnerability in Cisco Application Services Engine could allow an unauthenticated, remote attacker
    access to a specific API on an affected device. The vulnerability is due to insufficient access controls
    for an API running in the Data Network. An attacker could exploit this vulnerability by sending crafted
    HTTP requests to the affected API. A successful exploit could allow the attacker to learn device-specific
    information, create tech support files in an isolated volume, and make limited configuration changes.
    (CVE-2021-1396)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-case-mvuln-dYrDPC6w
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9c60100");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw14124");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw55819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw14124, CSCvw55819");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(306, 552);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_services_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_application_services_engine_detect.nbin");
  script_require_keys("installed_sw/Cisco Application Services Engine");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Cisco Application Services Engine', port:port, webapp:TRUE);

var constraints = [
  {'min_version':'1.1', 'fixed_version':'1.1.3.5', 'fixed_display':'1.1(3e)'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
  );