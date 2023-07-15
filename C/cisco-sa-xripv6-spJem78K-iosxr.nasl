#TRUSTED 57e2772d2dbdd5d5fee374602f8f91b7c4e746023985c31dcea67a60dd04648bc6c962fa2a258b63986bcb1e6e0587aeeee839ae8d7ad7e2b94b02b1441785863dedb47709b7d8d832b7e7b9608fb95c8131d2ded02c4f731996de76573b9dc2d7a52c3a365a65627df948acdbf59915b885ba0cfecf9b46c2a7f9ea86c1d84e30b7f0a9947c1b95fcb6b932b8ee839a56cf4e81f3c4b28fecedde267c79f2921c4cbce0e84c05dfc0db6e18512a963d68b42d00ba41b6326feb63c7bd7aa4831ff66271ffc1049e92c77b0e58aaf381c4f3bfe11b06eeb3625788f59e7dd2c6c9571a9f2ef62c5256d525b23c8edf10f83ecf3b771393f4a09854734ac9491820656eec51f5c711a336747abeebf8ea190a56f0963b643c1a2e0ef887f7e3c2de6d1f006359e859b0ab1e64249d1c82312a6d166802225172bb1fd4cd2f7896edb463b43f103852ebb866f0a9d37e34dbe5523a0f5671caf333ac83ee5e66ad96c40c1e1ac4c93270ead95ccbe37f3bb149c2d8e35842fd6386ac8ca14f80b96daabaaed0204614d92e113d5c20133373395d50733c8f49225a55220e644d6c626aac7182241842728d4eba92d950d94e8f5cec6ff5c41febb2601875c5c09ed80f811070349316fbdc0e35de9e32148e6b1491aeddd4e0106293924651d5cf5295df0b02a195021223cfd6a133eb9a65579992398b062367ddd86ead4af00b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147893);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1268");
  script_xref(name:"IAVA", value:"2021-A-0062-S");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv45504");
  script_xref(name:"CISCO-SA", value:"cisco-sa-xripv6-spJem78K");

  script_name(english:"Cisco IOS XR Software IPv6 Flood DoS (cisco-sa-xripv6-spJem78K)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, IOS-XR is affected by a denial of service vulnerability due to the software
incorrectly forwarding IPv6 packets that have an IPv6 node-local multicast group destination and are received on the
management interfaces. An unauthenticated, adjacent attacker can exploit this, by connecting to the same network as the
management interfaces and injecting IPv6 packets that have an IPv6 node-local multicast group address destination, to
cause an IPv6 flood on the corresponding network, resulting in network degradation or a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-xripv6-spJem78K
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57255a2d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv45504");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv45504.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1286");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(1076);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# No good way to check for workaround
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco IOS XR');

model = tolower(product_info['model']);

if ('ncs1k' >< model || 'ncs1001' >< model)
{
  smus['6.3.1'] = 'CSCvv45504';
  smus['6.5.2'] = 'CSCvv45504';
}

vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '6.7.3'},
  {'min_ver' : '7.0', 'fix_ver' : '7.1.3'},
  {'min_ver' : '7.2', 'fix_ver' : '7.2.2'},
  {'min_ver' : '7.3', 'fix_ver' : '7.3.1'}
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvv45504',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  smus:smus
);
