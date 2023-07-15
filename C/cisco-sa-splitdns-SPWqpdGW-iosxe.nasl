#TRUSTED a784260bdb3524f34fdeac30c8d9ad53cca9a6ffb299dc09783f6e658d1738370ec8ce017584e2cdfec8cdc609f4fc35f1c71f90c273e678f2d658e98a6446dcbc71fc6c954b15351e840e0ef1c7b759f395a0d4c90b4233ef5e41a886c78949366542e8b15e33ee93fe42e4872cef8b9f1659fa055245a96e1bb63331ab58ea3c510c1e2ab26392b863bcca008cded848d07d57d542d4462ecc8ea3a0a5f51f0d63fa1b3a5ba4b8773b2df5731b83915f3ca5f51bd36bfd1b7526991f002481e2f957bf4401e0fcde3783e3ff47e2a84ae9b5926b3036234d37b12b60c52f068d2dc6797e90532ff55820e80e33fd508305be9d97671283969c0c990fbb609553f8d18e8ffebc84985e56ab557b39e4eafc48f967218407426f2aa839688107e6b7c271f1fb80510249c16a620c499c8131eb166f5fcd7e8c1fc7e578654f606467373675f28ba1ba42aad193cb5ed033f926f1434b82051265e2414ccc2228ab8ada58f1d7e223b00c60c4b3f132e413d53448395cf0b328c4809cf98667379f73da2ad905ca41b8503211c770b76b42d99a98523e9bd77c4829d88e4bd86d7ab6ae35e9dde7cbd645d84cded282d928493bc2bb4f066761a4f8eb4b69e6e112f8242ae5f49cf538363e4e4b0be0e78329d0aba9531ef697dcfa4d697e5d3775423e69150fc5488b7a6d2b420f3172cf863357ecd4edbd73f8c89efd81b6a5
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141171);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2020-3408");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt78186");
  script_xref(name:"CISCO-SA", value:"cisco-sa-splitdns-SPWqpdGW");
  script_xref(name:"IAVA", value:"2020-A-0439");

  script_name(english:"Cisco IOS XE Software Split DNS DoS (cisco-sa-splitdns-SPWqpdGW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability
as the Split DNS feature's regular expression (regex) engine may time out when processing the DNS name list
configuration. An unauthenticated, remote attacker could cause an affected device to reload, resulting in a denial of
service.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-splitdns-SPWqpdGW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2f37dff");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt78186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt78186");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3408");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(185);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');


vuln_versions = make_list(
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1c',
  '16.10.1d',
  '16.10.1e',
  '16.10.1f',
  '16.10.1g',
  '16.10.1s',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.11.2',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t',
  '16.12.1w',
  '16.12.1x',
  '16.12.1y',
  '16.12.2',
  '16.12.2a',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3a',
  '16.12.3s',
  '16.5.2',
  '16.5.3',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.4a',
  '16.6.4s',
  '16.6.5',
  '16.6.5a',
  '16.6.5b',
  '16.6.6',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1c',
  '16.8.1d',
  '16.8.1e',
  '16.8.1s',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.1a',
  '16.9.1b',
  '16.9.1c',
  '16.9.1d',
  '16.9.1s',
  '16.9.2',
  '16.9.2a',
  '16.9.2s',
  '16.9.3',
  '16.9.3a',
  '16.9.3h',
  '16.9.3s',
  '16.9.4',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1t',
  '17.2.1v'
);

workarounds = make_list(CISCO_WORKAROUNDS['ip_dns_split_dns']);

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt78186',
  'cmds'     , make_list('show running-config | section ip dns')
);

cisco::check_and_report(
  product_info:product_info,
  vuln_versions:vuln_versions,
  workarounds:workarounds,
  reporting:reporting
);
