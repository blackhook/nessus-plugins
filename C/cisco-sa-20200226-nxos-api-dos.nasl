#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134219);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/19");

  script_cve_id("CVE-2020-3170");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp94847");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-nxos-api-dos");
  script_xref(name:"IAVA", value:"2020-A-0087");

  script_name(english:"Cisco NX-OS Software NX-API Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the NX-API feature of Cisco NX-OS due to incorrect validation of the
HTTP header of a request that is sent to the NX-API. An unauthenticated, remote attacker can exploit this issue, via a
specially crafted HTTP request to NX-API, to cause the NX-API process to stop responding.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-nxos-api-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ead82886");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp94847");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp94847");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3170");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

version_list=make_list(
  '8.3(2)',
  '8.3(1)',
  '8.2(2)',
  '8.2(4)',
  '8.2(3)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1b)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)',
  '7.3(2)D1(1d)'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['nxos_nxapi'];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvp94847'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
