#TRUSTED 75aeac28d076e47dbf1c33b517cb6af0315eabcea5e42a22ce478e56274a0c7e68f9cc4e7a3a487407f7f319eb2eb2e8ae0daa50358d317c9eb51dd379fc200a74e4345e63dd5181b15aea571c238cdf4ad5f5a8b982165b9152491d340c3076aa233dd86d4fe91963b097a3d497ffc9e12bd38f238fbc3ac35745d6561463538a0125ce441bed51edaf5ab7d26ef19349976654555da299a16fba16eabe400ba47e250de20682f60316e6e379747c1b6caebb57f2a4b01bd9fa03daec38730b8a514c1dffd0736319012cbabedfba28f721da0ee398f36a920d0811bdfd1ca84838ef64d1ab763e1a5ecc3207764600047a6da6855f4da61f6de67d44a6c177449c00efef444776f37110881fce50fea9308ab8be1c43f992bd5199dcafed2b8db1942d877df13e069e227933379e2ec771a74875b60b55ccbb0e55a1417527035ba19156ccc18154a4d0245e9c3949a25d3863cff85c9f410837a35afbade91d4e032b51e595ad97848ee3a2c68d5102cf4d2901a38a4a9eeb512fa7a87db94fd6da520e3e04140954e5ffb5d1c59a2f798d604a8f1ddc5c515e809e2f5d1bfd02f7b412d2f6e75552d7657e2eef42c099bd24ae5f6d033a5a594fdc3a329efd8d2114fc6c73a23c47ccd8d9aeda83de8ad44c659f458cdebb087dc961f77f162608c104ff0b8b46b30efc90812123137335b83980cc5fdf614c980f5793e8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128325);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/08");

  script_cve_id("CVE-2019-12643");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn93524");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo47376");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190828-iosxe-rest-auth-bypass");
  script_xref(name:"IAVA", value:"2019-A-0316");

  script_name(english:"Cisco REST API Container for IOS XE Software Authentication Bypass Vulnerability");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability
in the Cisco REST API virtual service container for Cisco IOS XE Software could allow an
unauthenticated, remote attacker to bypass authentication on the managed Cisco IOS XE device.
The vulnerability is due to an improper check performed by the area of code that manages the
REST API authentication service. An attacker could exploit this vulnerability by submitting
malicious HTTP requests to the targeted device. A successful exploit could allow the attacker
to obtain the token-id of an authenticated user. This token-id could be used to bypass authentication
and execute privileged actions through the interface of the REST API virtual service container
on the affected Cisco IOS XE device. The REST API interface is not enabled by default and must
be installed and activated separately on IOS XE devices. See the Details section for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190828-iosxe-rest-auth-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc00ad5e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn93524");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo47376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvn93524, CSCvo47376");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];

if (model !~ "ISR" &&
    model !~ "ASR1" &&
    model !~ "CSR1"
   )
  audit(AUDIT_DEVICE_NOT_VULN, model);

version_list=make_list(
  '3.7.8S',
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2aS',
  '3.10.2tS',
  '3.10.7S',
  '3.10.8S',
  '3.10.8aS',
  '3.10.9S',
  '3.10.10S',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.0S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.7S',
  '3.13.6aS',
  '3.13.6bS',
  '3.13.7aS',
  '3.13.8S',
  '3.13.9S',
  '3.13.10S',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
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
  '3.16.6S',
  '3.16.5aS',
  '3.16.5bS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.7aS',
  '3.16.7bS',
  '3.16.8S',
  '3.16.9S',
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
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3S',
  '3.18.4S',
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
  '3.18.3SP',
  '3.18.4SP',
  '3.18.3aSP',
  '3.18.3bSP',
  '3.18.5SP',
  '3.18.6SP',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.1d',
  '16.8.2',
  '16.8.1e',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.3s',
  '16.9.3a',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1c',
  '16.10.1e',
  '16.10.1d',
  '16.10.2',
  '16.10.1f',
  '16.10.1g',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1s',
  '16.11.1c',
  '17.4.1',
  '17.5.1',
  '17.6.1'
);

workarounds = make_list(CISCO_WORKAROUNDS['iosxe_rest_api_service_container']);
vuln_containers = make_array(
  'mgmt',
  make_list(
    '1.4.1',
    '1.5.1',
    '1.6.1',
    '1.7.1',
    '1.7.2',
    '1.8.1',
    '162.1',
    '99.99.99'
  ),
  'csr_mgmt',
  make_list(
    '03.16.03',
    '03.16.04',
    '1.0.0',
    '1.2.1',
    '1.3.1',
    '1.4.1',
    '1.5.1',
    '1.6.1',
    '1.7.1',
    '1.8.1',
    '99.99.99',
    '2017.6',
    '2017.10',
    '162.1',
    '163.1'
  )
);

workaround_params = {'vuln_containers' : vuln_containers};

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn93524, CSCvo47376'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list,
  router_only:TRUE
);
