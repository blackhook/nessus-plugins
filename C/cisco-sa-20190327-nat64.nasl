#TRUSTED 0efbb4d44fa2a1c00df0b115764895c7c4b01aab1b990b41e1c9cdaa3aa349256620e24473ed1482975910f468d57514e31902686247981e345dd17996de5b397aa8e72c5cbc9068b9cd8f87e8efca4110e2a2fd41b423eec3a71c6cfa231cb99cf55fab1d8046ae6021ce72843097e1f5a731519f040a3d6e8d6c0b39b81302725fe98de426b6af16aeec5f05120d424fcd1b3407715760930a5632e85d093c77ae5b6d36c2161e6fe32065cbc74bd83f79a6e43d3a5fe8ec8d351ae666b11657c80f37e457d45d7c546fb981c7d6a573d73130653ef55cafa9717753c24bb7aff0491b8c132915ebf804aa5aceb188571dd6f6c674510cb3c25f9ffdb3a1f11e7068fa66645b84decd7759ce439846e4232374a076acd1ae3c133423e1057fb5084d763216bf5f48724b4a572823fddf179a1923ed11bc8f62e71ac06e7126aad99fd34e16e91f6c9065d1dc9285b49243c7059549f9b87a71366e6946d90af3e722f82d0077393ad0e1dd7f70573b0df4a3c5cf78f85a2da035d782516945260095d94ad3f77c7e736b63af97375193260084ff53b4925a915cb09f9904b9bac76f40fdd8a343e371873282cc8cae687dd480aa9521d941b83e6f6f6c5ca02948cd612053cea89db725a5dd0234a8f5b631c54c532be248c89a6b2fe1a31ca05bf7f1d15ea40ace2d676143eee0bd0fb5595ab01086f2fe104cd552dfaf3e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132723);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2019-1751");
  script_bugtraq_id(107601);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk61580");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190327-nat64");

  script_name(english:"Cisco IOS Software NAT64 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of IOS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS is affected by following
vulnerability

  - A vulnerability in the Network Address Translation 64
    (NAT64) functions of Cisco IOS Software could allow an
    unauthenticated, remote attacker to cause either an
    interface queue wedge or a device reload.The
    vulnerability is due to the incorrect handling of
    certain IPv4 packet streams that are sent through the
    device. An attacker could exploit this vulnerability by
    sending specific IPv4 packet streams through the device.
    An exploit could allow the attacker to either cause an
    interface queue wedge or a device reload, resulting in a
    denial of service (DoS) condition. (CVE-2019-1751)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190327-nat64
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?44713557");
  # http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-71135
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ce3e2e9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk61580");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk61580");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1751");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS');

version_list=make_list(
  '15.8(3)M0b',
  '15.8(3)M0a',
  '15.8(3)M',
  '15.7(3)M3',
  '15.7(3)M2',
  '15.7(3)M1',
  '15.7(3)M0a',
  '15.7(3)M',
  '15.6(3)M5',
  '15.6(3)M4',
  '15.6(3)M3a',
  '15.6(3)M3',
  '15.6(3)M2a',
  '15.6(3)M2',
  '15.6(3)M1b',
  '15.6(3)M1a',
  '15.6(3)M1',
  '15.6(3)M0a',
  '15.6(3)M',
  '15.6(2)T3',
  '15.6(2)T2',
  '15.6(2)T1',
  '15.6(2)T0a',
  '15.6(2)T',
  '15.6(1)T3',
  '15.6(1)T2',
  '15.6(1)T1',
  '15.6(1)T0a',
  '15.6(1)T',
  '15.5(3)M8',
  '15.5(3)M7',
  '15.5(3)M6a',
  '15.5(3)M6',
  '15.5(3)M5a',
  '15.5(3)M5',
  '15.5(3)M4c',
  '15.5(3)M4b',
  '15.5(3)M4a',
  '15.5(3)M4',
  '15.5(3)M3',
  '15.5(3)M2a',
  '15.5(3)M2',
  '15.5(3)M1',
  '15.5(3)M0a',
  '15.5(3)M',
  '15.5(2)XB',
  '15.5(2)T4',
  '15.5(2)T3',
  '15.5(2)T2',
  '15.5(2)T1',
  '15.5(2)T',
  '15.5(1)T4',
  '15.5(1)T3',
  '15.5(1)T2',
  '15.5(1)T1',
  '15.5(1)T',
  '15.4(3)M9',
  '15.4(3)M8',
  '15.4(3)M7a',
  '15.4(3)M7',
  '15.4(3)M6a',
  '15.4(3)M6',
  '15.4(3)M5',
  '15.4(3)M4',
  '15.4(3)M3',
  '15.4(3)M2',
  '15.4(3)M10',
  '15.4(3)M1',
  '15.4(3)M',
  '15.4(2)T4',
  '15.4(2)T3',
  '15.4(2)T2',
  '15.4(2)T1',
  '15.4(2)T',
  '15.4(1)T4',
  '15.4(1)T3',
  '15.4(1)T2',
  '15.4(1)T1',
  '15.4(1)T',
  '15.4(1)CG1'
);

workarounds = make_list(CISCO_WORKAROUNDS['include_nat64']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk61580'
);

cisco::check_and_report(product_info:product_info, 
                        workarounds:workarounds,
                        workaround_params:workaround_params,
                        reporting:reporting,
                        vuln_versions:version_list);
