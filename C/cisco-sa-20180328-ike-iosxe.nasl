#TRUSTED 4d2600329c398f330acf1ecabc0cb3bed11dd12acfe984f10202884fdb47d267997669641aa92501dd9a5fcc66c128bdbb47641bf6a3f7c539844dda11da131f0959e5291896f5ec771a87e0d3fbeeff9ad40691d3e68927a2cb6ddc49cd6e9fcb210ef6691b8415806c69a32c08563d7c5a6cd63967864ee6d804c4f57e4878c84cdfb1e71c95cf40fe0dbbfbb300541fe78bb408a56286903f723e37c4a60204f41606293f9a1f841e63c4f5709d23c17c23acdae5fb4a83360b9670320fb19c5ed3d111f86ce07e5cecb420b8d2e934ba88e30cc0eaa1dc0811a67448ca00a7b500f886690f63fcbd457f3cafe1945698e4ebde525adf748b1808ee71046658510fd1543c1f77a5e0ae536fbd5da9b8adca5f3f1e6a30ff588295edab7ed5d5cab4e770d4773b70da474a238bf7236a047d36035e5a7ea9a6b8daab018345d3fac381ef01f4e169ea246fe5eaa4cceac04e6bd3accda521ee60fbd29673673f683db1aadd5868c2fc4b18974ea03d720e4312bd7224926e10cea0079b9914460682c01f8b7f7b1891f5aac2ff02a3339b4dd00df07b693a0c67f62e114e58824020b83bb15f4208ed4081e3136b4c8633a7c0b555816c87787dfb85ccd6b5b85d3f6cb431010b54ba9782ccba16e6e806187a1a35afa5974755e6fe4d42af618f0cddf402006d6e6f1ed6cccef2b1cadb1fecd056daa8a34e80763427132a
#TRUST-RSA-SHA256 aaf74cf434523a675d00927a0424246ab0fcadbede9ba666188f2957da2d02d1e6b63aa5c9c4292b0376869f4251426a16a510cca871a64ce2945fdbfd2ca5e59bb78a426bf87b1adf2909a2f91f1ca96a0dbb95c555dc874c8b5f486d0d646c2edb83a3f8406b8a4b01bd1674b9d5e1612a0c9d8782b5a4e64615b416f58d335f344fc630a9fcb811f34055855b01d9b82795e62e2d352b662fcf11891294667737cb2c45a32f711afaad235d9219919a03fbd23486bc1d95e9501876cc374f2911833992989ca51fbb1c4db2e8686e6792e7d57f3ceba30435361cd789fe9381f22ec53bf0ce702597ff2a66b1748db1d953d158dc8e056cc72d00b681dae58b0b35b896f380d317d5666efb9e806590a3bc33ed5424dfc60d9fa9791504945b13c582386439ad613b14e141dc333b8c8a07119928407bfdb951f1e97d1278571d6656ca26b5207fc4710b767f40714e7d15caa282d78aa3bedd67ee9d1c519249a7d80f585fc14ec774f9b15757202ca7b641cd53f4aeae4f11c74405258800de6629924fb566d034304ad21fe80e14109d639b298e5be14bd0cd07285342fdb1b35d69d1b3c8f093dae34635f9e6a6ae610de6957d7e1f80bf3ea248adaabbd29860bb4dd7eb91a26d3041a23953db89f227dafbceec7b7b7e80bc631f95745cde32f68958eee4d82a7f08349c08c4a1e416e6283012a042512978686931
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131326);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2018-0158");
  script_bugtraq_id(103566);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf22394");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-ike");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Memory Leak (cisco-sa-20180328-ike)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Internet Key Exchange Version 2 (IKEv2) module due to incorrect processing of certain IKEv2 packets. An
unauthenticated, remote attacker can exploit this, by sending crafted IKEv2 packets to an affected device, in order to
cause a memory leak or a reload of an affected device, leading to a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-ike
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c962b883");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf22394");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCvf22394.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0158");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list = make_list(
  '3.16.0S',
  '3.16.1S',
  '3.16.0aS',
  '3.16.1aS',
  '3.16.2S',
  '3.16.2aS',
  '3.16.0bS',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.4gS',
  '3.16.5S',
  '3.16.4cS',
  '3.16.4dS',
  '3.16.4eS',
  '3.16.5aS',
  '3.16.5bS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.3S',
  '3.17.4S',
  '16.1.1',
  '16.1.2',
  '16.1.3',
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.4.1',
  '16.4.2',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1gSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.18.2SP',
  '3.18.1hSP',
  '3.18.2aSP',
  '3.18.1iSP',
  '3.18.3bSP',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE'
);

workarounds = make_list(CISCO_WORKAROUNDS['show_udp_ike'],CISCO_WORKAROUNDS['show_ip_sock_ike']);
workaround_params = make_list();

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvf22394',
  'cmds'     , make_list('show udp', 'show ip sockets')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
