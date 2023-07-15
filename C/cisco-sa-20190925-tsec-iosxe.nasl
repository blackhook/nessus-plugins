#TRUSTED 4b4a69708d34661bbadec90cd473ccc125c0a658ff6c955ec2b9ed1518604e1acc67449925b8bc8457e84bb739b79d64ccef566af005fabda7a1401ce2de1b1dec41fa4407cf269db6a7a0b8c30ac963fcd0ea5b4eb1aadee6637928eb43cd53a08f8f93bff8a6454cd41be3232f473a4db3ac70703af6382f45c67ac3a33d0cfe10b709e88ff2607c6bb24c3bab9681fea3dbafb0fcb8a04bd2d1a249ccb74758407ee24e15c1d261d97739f5d2ebef243a1ea8b0a8e97649a54bfddd6084deb33d41d980381626768e47665b735f927e09178ac6d7a0209bf24de656d05ebd808e1c4adec8ad05f8a37188454c679e7e6c5bd4d918b5291fbc7ad2794a8671262b4863929dcdcdee4e88999eb55a16b245b69cf2f0c9741f0abeffeffe62907b5fab9243179246ad70a19deb39962278c0a3c2654c92d291269609c463a1d5b1953ffa33df090ac54a3859c67ffa201c332d291a568fb8505e807d4a3f078657ccd54288f7a07f66e14deed3d99face5cdf4bf6b6194f23478d2e21b61df654b99e7a5782c3695217291de18bf415702d228354efa4eac4d1ba1a8c2dd98d77aad1b2a9c0a3c1d4b4877f472f20822d00956736d41646c399162ca4c80bf8af5075600fb00e9f8659798cc91a23152be61124720f55635a0dd401edf8609a714f65e9a75d77f62d91f34fe54fcdaed1ba94d6d16c192057238c793725baeb0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129943);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12669");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg56762");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm92998");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-tsec");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Change of Authorization DoS (cisco-sa-20190925-tsec)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in the RADIUS Change of Authorization (CoA) code of Cisco TrustSec within
Cisco IOS XE software due to improper handling of malformed packet. An unauthenticated, remote attacker can exploit this
issue, via sending a malformed packet to an affected device, to cause the DoS condition on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-tsec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48ce2f62");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg56762");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm92998");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvg56762, CSCvm92998");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12669");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('audit.inc');
include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

version_list=make_list(
  '3.9.2bE',
  '3.9.2E',
  '3.9.1E',
  '3.9.0E',
  '3.8.8E',
  '3.8.7E',
  '3.8.6E',
  '3.8.5aE',
  '3.8.5E',
  '3.8.4E',
  '3.8.3E',
  '3.8.2E',
  '3.8.1E',
  '3.8.0E',
  '3.7.5E',
  '3.7.4E',
  '3.7.3E',
  '3.7.2E',
  '3.7.1E',
  '3.7.0E',
  '3.6.9aE',
  '3.6.9E',
  '3.6.8E',
  '3.6.7bE',
  '3.6.7aE',
  '3.6.7E',
  '3.6.6E',
  '3.6.5bE',
  '3.6.5aE',
  '3.6.5E',
  '3.6.4E',
  '3.6.3E',
  '3.6.2aE',
  '3.6.2E',
  '3.6.1E',
  '3.6.10E',
  '3.6.0bE',
  '3.6.0aE',
  '3.6.0E',
  '3.5.3E',
  '3.5.2E',
  '3.5.1E',
  '3.5.0E',
  '3.4.6SG',
  '3.4.5SG',
  '3.3.5SE',
  '3.3.4SE',
  '3.3.3SE',
  '3.3.2XO',
  '3.3.2SE',
  '3.3.1XO',
  '3.3.1SE',
  '3.3.0XO',
  '3.3.0SE',
  '3.2.9SG',
  '3.2.0JA',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '3.10.2E',
  '3.10.1sE',
  '3.10.1aE',
  '3.10.1E',
  '3.10.0cE',
  '3.10.0E',
  '16.9.3s',
  '16.9.3h',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.4',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

reporting = make_array(
'port'     , product_info['port'], 
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvg56762, CSCvm92998',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_versions:version_list, router_only:TRUE);
