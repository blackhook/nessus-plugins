#TRUSTED 0ad7bba30319bc8b4a8f6d90d334b67e3a47e4d5536bd0784cc99adf5e97f710d5dde6e21e12f1f543eb7521de949b7763d04e12b7e5ff3dbc32826d4a635984c24c1a1245e8d43d46e81174671cc7f46d0cfbe178c95321f6e04ed0920a1aa6aaf4b3f0244f07218c3270b0d1854640906a7e8a918e0bbecb759fde4bc8c5f7a8973169d33eca051aaf4c49f38eb783f6e7005045a5f5aa9a04e9ed1db67f1589e130870c3bb2cb61edf7347243dc029bfe040b64b5dbedd09c6dfa73cbccb3f175512b7cdc05e43478a3446b398399c9f58e6fe95b16801b6e335089ddc863e3ce0336ec27ba42c54515f1f47fd83e5141bbe3220e692451e97da0734b2cfd3245fcef536d78c26e7b0474f53b3b7a5f8c5ed4e113c341929654962121f7802fd0d74ef6dc045e2cef5554a3916944f38c5c1b795354712a1ab0010bcdde8968f6b3505b74b939e239812861dc582d59eee8bbd6bf435ffa7c7a1311220292ecae3d769bd6c3c5587d603befe1a574d19e86e24a1d9913775f904e6e5dbc60a1fa0c2bbb544764f0771bd3ada8b41d9fcb8b567fcd325e40549252033aa63a67ebea366c29da15c6443ce064820b17b6c558dc06f47f27d1c64ed5e1c562009d8b61d339862660cdf7639046451599564ccd910b3150461c9434a996cf6c140a339b542374555b11bd85a2ff39dfdd8423780a06c73e5d838edcf726dae90f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126446);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-1727");
  script_bugtraq_id(108341);
  script_xref(name:"IAVA", value:"2019-A-0173");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh24788");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi99288");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-pyth-escal");

  script_name(english:"Cisco NX-OS Software Python Parser Privilege Escalation Vulnerability");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Python scripting subsystem of Cisco NX-OS
Software could allow an authenticated, local attacker to escape the
Python parser and issue arbitrary commands to elevate the attacker's
privilege level. The vulnerability is due to insufficient
sanitization of user-supplied parameters that are passed to certain
Python functions in the scripting sandbox of the affected device.
An attacker could exploit this vulnerability to escape the scripting
sandbox and execute arbitrary commands to elevate the attacker's
privilege level. 

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-pyth-escal
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4760bae3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99284");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh24788");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99282");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi99288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bugs ID
CSCvi99284, CSCvh24788, CSCvi99282, CSCvi99288");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');


if (('MDS' >< product_info['device']) && (product_info['model'] =~ '^90[0-9][0-9]')) bugIDs = 'CSCvi99284';
else if ('Nexus' >< product_info['device'])
{
  if (product_info['model'] =~ '^3[05][0-9][0-9]' || product_info['model'] =~ '^90[0-9][0-9]') bugIDs = 'CSCvh24788';
  else if (product_info['model'] =~ '^36[0-9][0-9]' || product_info['model'] =~ '^95[0-9][0-9]') bugIDs = 'CSCvi99282';
  else if (product_info['model'] =~ '^7[07][0-9][0-9]') bugIDs = 'CSCvi99284';
}

if (isnull(bugIDs)) audit(AUDIT_HOST_NOT, 'affected');

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '8.1(1a)',
  '8.1(1)',
  '8.0(1)S2',
  '8.0(1)',
  '7.3(3)N1(1)',
  '7.3(2)N1(1)',
  '7.3(2)N1(0.296)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1A)',
  '7.3(2)D1(1)',
  '7.3(1)N1(1)',
  '7.3(1)N1(0.1)',
  '7.3(1)DY(1)',
  '7.3(1)D1(1B)',
  '7.3(1)D1(1)',
  '7.3(0.2)',
  '7.3(0)N1(1b)',
  '7.3(0)N1(1a)',
  '7.3(0)N1(1)',
  '7.3(0)DY(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.0(3)I7(2)',
  '7.0(3)I4(3)',
  '7.0(3)I4(2)',
  '7.0(3)I4(1)',
  '7.0(3)I3(1)',
  '7.0(3)I2(5)',
  '7.0(3)I2(4)',
  '7.0(3)I2(3)',
  '7.0(3)I2(2e)',
  '7.0(3)I2(2d)',
  '7.0(3)I2(2c)',
  '7.0(3)I2(2b)',
  '7.0(3)I2(2a)',
  '7.0(3)I2(2)',
  '7.0(3)I2(1a)',
  '7.0(3)I2(1)',
  '7.0(3)I1(3b)',
  '7.0(3)I1(3a)',
  '7.0(3)I1(3)',
  '7.0(3)I1(2)',
  '7.0(3)I1(1b)',
  '7.0(3)I1(1a)',
  '7.0(3)I1(1)',
  '7.0(3)F3(4)',
  '7.0(3)F3(3c)',
  '7.0(3)F3(3b)',
  '7.0(3)F3(3a)',
  '7.0(3)F3(3)',
  '7.0(3)F3(2)',
  '7.0(3)F3(1)',
  '7.0(3)F2(2)',
  '7.0(3)F2(1)',
  '7.0(3)F1(1)',
  '7.0(3)',
  '7.0(2)N1(1a)',
  '7.0(2)N1(1)',
  '7.0(2)I2(2c)',
  '7.0(1)N1(3)',
  '7.0(1)N1(1)',
  '7.0(0)N1(1)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , bugIDs
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
