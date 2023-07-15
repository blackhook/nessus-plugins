#TRUSTED 8dfbe3284748623633caebf8c0158214b337d9b8d768cea240e87585c9a6473187d2a13f5490c6a712c2ea7c725ac12277d61816d20482ee941287ee2b08e68bf1cad46603dbca6c3c2641d0e3bb980065b157bce9efd9b3992b77456689e0af415ebba03afb3c2a793f251d47d539a404c66ab12c2782be760a560e91a08f83e59686c39c6380af49c7ea540e249f100c90067923868759280191e55fbac3b2c3f873d2092a6f7d1e53ac357d603960ec7e01e276cc72d46ed41d72c6afc5ad3bcd1d64d395c12d99775365bdcc2b6f509c7f963996103fb7102a2a42c31f26cc9b4622bdab0c31816ecdd4c82fed066db72b53fdfae5fdf4dc2a6149c7787619d3fd8f724d16be0f2c6c07cfc28c52effe41236c1bd6c06819a8d53e9c26a282c02f4dc2216c0fbba115df548840dd6bf641ea0efe2dfaf178247629668d424b86a264ab04cf5d985357663d54c3bba18630ae7ae810cefcf1c81f73690efc206cb3cfb1454b09ff3b2092f3439659fab0255ff6be4db85c6439745644bd010f62d19030ed80c6aa354c250bd027ee4eac40ed636e8dd63d1273c732f94cdda80955a46e030bdb0fb1a22672afdccf507d1c1973c928d1cba157467e4eff3eede69e209a778e4f84485a65a56d4d92eae42404e0023c0111dfcf6875257d2b9443bef52f598ea5d43b49a890dd30bd7fc90ec2277d462b91f9d2bd0ddf934a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136973);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/04");

  script_cve_id("CVE-2019-1697");
  script_bugtraq_id(108182);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn20985");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-ftds-ldapdos");

  script_name(english:"Cisco Adaptive Security Appliance Software Lightweight Directory Access Protocol Denial of Service Vulnerability (cisco-sa-20190501-asa-ftds-ldapdos)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco ASA device is affected by a vulnerability 
in the implementation of the Lightweight Directory Access Protocol (LDAP) feature in Cisco
Adaptive Security Appliance (ASA) Software and Firepower
Threat Defense (FTD) Software could allow an
unauthenticated, remote attacker to cause an affected
device to reload, resulting in a denial of service (DoS)
condition.The vulnerabilities are due to the improper
parsing of LDAP packets sent to an affected device. An
attacker could exploit these vulnerabilities by sending
a crafted LDAP packet, using Basic Encoding Rules (BER),
to be processed by an affected device. A successful
exploit could allow the attacker to cause the affected
device to reload, resulting in a DoS condition.
(CVE-2019-1697)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190501-asa-ftds-ldapdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bc6d5791");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn20985");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvn20985");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

model = product_info['model'];
if (model =~ '^55[0-9][0-9]' || model =~ '^1000v')
  audit(AUDIT_HOST_NOT, 'an affected Cisco ASA product');

vuln_ranges = [
  {'min_ver' : '9.6',   'fix_ver' : '9.6.4.25'},
  {'min_ver' : '9.7',   'fix_ver' : '9.8.4'},
  {'min_ver' : '9.9',   'fix_ver' : '9.9.2.50'},
  {'min_ver' : '9.10',  'fix_ver' : '9.10.1.17'}
];

workarounds = make_list(CISCO_WORKAROUNDS['show_aaa_server_protocol_ldap']); 
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn20985',
  'cmds'     , make_list('show aaa-server protocol ldap')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);