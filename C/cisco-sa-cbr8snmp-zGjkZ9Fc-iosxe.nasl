#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165349);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-1623");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw60229");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cbr8snmp-zGjkZ9Fc");

  script_name(english:"Cisco IOS XE Software for cBR 8 Converged Broadband Routers Simple Network Management Protocol DoS (cisco-sa-cbr8snmp-zGjkZ9Fc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Simple Network Management Protocol (SNMP) punt handling function of Cisco cBR-8 Converged 
Broadband Routers could allow an authenticated, remote attacker to overload a device punt path, resulting in a denial 
of service (DoS) condition. This vulnerability is due to the punt path being overwhelmed by large quantities of SNMP 
requests. An attacker could exploit this vulnerability by sending a large number of SNMP requests to an affected 
device. A successful exploit could allow the attacker to overload the device punt path, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cbr8snmp-zGjkZ9Fc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?723bc734");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw60229");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# We cannot test for the full vulnerable condition
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var version_list=make_list(
  '3.15.0S',
  '3.15.1S',
  '3.15.1xbS',
  '3.15.2S',
  '3.15.2xbS',
  '3.15.3S',
  '3.16.0S',
  '3.16.1S',
  '3.16.2S',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0aS',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.2aSP',
  '3.18.3SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.4SP',
  '3.18.5SP',
  '3.18.6SP',
  '16.5.1',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1d',
  '16.8.1e',
  '16.9.1',
  '16.9.1a',
  '16.10.1',
  '16.10.1c',
  '16.10.1d',
  '16.10.1f',
  '16.10.1g',
  '16.12.1',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.1z',
  '17.2.1'
);

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvw60229',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info       : product_info,
  reporting          : reporting,
  vuln_versions      : version_list
);