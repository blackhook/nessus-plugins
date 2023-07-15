#TRUSTED 59263c95d664814e08e4ed78cc866dac625e267562b16cf13f13f58644685860b5bcc69ca4de4ba4e75ed4db45b57dbbb36cbf0de4b3d688e2f65d2e71d850f393fe59f29dd33d2bde4d47c8fc00e6f0870079821522dfc6f7c10531c7549db56915e8f34ad8c1e9f8430658b7bd456edc304f9532c12f7b088a8ad3779cc065e1639213b677e6789a36aeb288c5d6d865ac7fe42382d8e166545aa2e0bfa5e7d82790d3ca1640841823a2750f70b8fc066550cf59153f325665dbb8abaaf43960f572f22a05e0944efa9b8ea257e606b03111bb0eb6c46667bdc323dae83983a2a84e874141f5dbf85a0b395a674c9802197c4fb71a265ada6c365bb6d8b6791c0eaaa988039801a9a96f90a78a26ad824397889658d96c9f8fa87df4c1816fbeb596ca8eba61134b0498532b14c8d8d5af929e425d142d93df15327840de10f5a490dd4e8e8f45164860e762d55ef6eba29c44de4a0352015c2a3e1cbb59be3c0c2d6a2ecad2dfc23776b0fc495ec6be349fabd703382a88d6756986af9c3d19b5c4ff16aaa6f3f0527205c7a97142a31a7095e4f9d422463d6afefea74bd5d739096f120d0db863b9b2816122efbc7045e5aa40743f26b38d861309b473358be10ab39a83aab0dde32d773b0103373a34b708b46e25f2592f211641e10497f084b09c96095f028c0aa804b2e5af9d776eb8e82ef38634ae3258734be4ba86
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139232);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3375");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11538");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdbufof-h5f5VSeL");
  script_xref(name:"IAVA", value:"2020-A-0348-S");

  script_name(english:"Cisco SD-WAN Solution Software Buffer Overflow Vulnerability (cisco-sa-sdbufof-h5f5VSeL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by a buffer overflow vulnerability. 
This could allow an unauthenticated, remote attacker to cause a buffer overflow on an affected device.
The vulnerability is due to insufficient input validation. An attacker could exploit this vulnerability 
by sending crafted traffic to an affected device. A successful exploit could allow the attacker to 
gain access to information that they are not authorized to access, make changes to the system that 
they are not authorized to make, and execute commands on an affected system with privileges of the 
root user.
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdbufof-h5f5VSeL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5771685");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11538");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt11538");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3375");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

version_list=make_list(
  '16.9.4',
  '16.9.3',
  '16.9.2',
  '16.9.1',
  '16.9.0',
  '16.12.2r',
  '16.12.1e',
  '16.12.1d',
  '16.12.1b',
  '16.12.0',
  '16.11.1a',
  '16.11.0',
  '16.10.4',
  '16.10.3b',
  '16.10.3a',
  '16.10.3',
  '16.10.2',
  '16.10.1',
  '16.10.0',
  ''
);

var sdwan = get_kb_item('Host/Cisco/SDWAN/Version');
var model_check = product_info['model'];

#Model checking for IOS XE SDWAN model only
if(model_check  !~ "^[aci]sr[14][0-9]{3}v?")
  audit(AUDIT_HOST_NOT, 'affected');

if(sdwan !~ "([0-9]\.)+")
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt11538',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
