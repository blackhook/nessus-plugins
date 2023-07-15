#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156946);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-20651");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa07032");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asdm-logging-jnLOY422");
  script_xref(name:"IAVA", value:"2022-A-0024");

  script_name(english:"Cisco ASDM Information Disclosure (cisco-sa-asdm-logging-jnLOY422)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An information disclosure vulnerability exists in Cisco Adaptive Security Device Manager (ASDM) due to the storage of
unencrypted credentials in certain logs. An authenticated, local attacker can exploit this, by accessing the logs on an
affected system, to view the credentials of other users of the shared device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asdm-logging-jnLOY422
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff810e91");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa07032");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa07032");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(532);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:asdm");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asdm_detect.nbin");
  script_require_ports("installed_sw/Cisco ASDM");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'Cisco ASDM';
var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

var constraints = [
  { 'min_version' : '7.15.1', 'fixed_version' : '7.17.1', 'fixed_display' : '7.17(1)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
