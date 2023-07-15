#TRUSTED 114f0c5e733c5a30154c39b6fe349be7cf994654ba960c6b32cb007b9b45729a4872bb956b4010ece758d74ab3226b45d8559fd28fed80499517844beee81edde36903eebb73f4d31da644a1617428e81145d35456648f85345b9b6a86a1bfff2850a35d50c1a5f9bbaf7079e460ea45b0f6a7e50a77ca4d17a77625161b5beb6159f43bce5dce7482bd2685013dd739efc317fdc38248f5e68a7e815c8cad62ed8dfc793360821b50d40142cab17a5ca755be8ac8340768c84ac778e6ffe5df85f1f0dca0cbedb6bd573916cb136ae8dcb67781d35dadd6f3bc19f2a4674bc1e67b850186a763b25e6aa6a7150d5095050b080371b65cc65b68d46611c8189ebc2feff77db87d6c0f304261f62955a9d21b78d4fbe0323426c2d62b646696c950dc714a1970dd87950445f1ce53a757d1bcbc72f6a399215d0e7362ec01f7efad6b103552af2e48de212e8afb7375697cacde9ef55bbdadd2b82f877e9ce5e36c21a6965561033360dafc2fcd815265a3fc4fd52fa18fd458503024d9b90ab3f4e29971379878178a144b87f9408636321d6d735ef6e269a02c3918d8b4916aa9b165ffd7992a21ec53b6466850f6263eb67df4a2dd0e95d8cffe59a4d9967bbbd5dc8986f5bda3227a37b406b8233ebe073573ad13e18c2ade807ea74fc1eedb4553eacfff7344fafdfef3e1752a84c1fff5f7826d3e704e2db90d1c5ca887
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132104);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/06");

  script_cve_id("CVE-2018-15372");
  script_bugtraq_id(105416);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh09411");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180926-macsec");

  script_name(english:"Cisco IOS XE Software MACsec MKA Using EAP-TLS Authentication Bypass (cisco-sa-20180926-macsec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by an authentication bypass vulnerability
in the MACsec Key Agreement (MKA) using Extensible Authentication Protocol-Transport Layer Security (EAP-TLS)
functionality due to a logic error. An unauthenticated, adjacent attacker can exploit this, by connecting to and
passing traffic through a Layer 3 interface of an affected device, if the interface is configured for MACsec MKA using
EAP-TLS and is running in 'access-session closed' mode. A successful exploit allows the attacker to bypass 802.1x
network access controls and gain access to the network.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180926-macsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?52021652");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh09411");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvh09411.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0); 
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.3bSP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['macsec_eap-tls'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvh09411',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
