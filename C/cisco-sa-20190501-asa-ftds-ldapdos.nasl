#TRUSTED a269bd44780489b72e1712ae2ea490a41cfa04a12b25c54cb56a0784f0c0d4449d037f886b820d9f94e8dec94974148d0109f1641957f1a20e181e7ec965b174344c12ffc201e28e781e561feffd4e265d57febcb88528995526d6f9f076e87ecceede3786835dd4ba44ac0714629868e4b9af2d90ba11f8e0f5973bf33703b5bf2ea9072551f6749b4cb66975596ecb140c4f7fa999686d7bd093e4a76cc71d865035513df8ddbfd17afe13558149f0696cde2bded780226e88dde1b2a12bab1ee0ee6a44b28c76c5a836043b1230124aa37f7f12af9df7e1aaebc478dbb0a028e1b5fdb2eda57e784eee471b9dcac1df435e99f69e589f2d0594293848404c7dd213ecaba4c840434e4822a1c3b2e58488a24fefeec32f4f9ce246bf3139dcbb08550401dcdbc8d4eec2c63910b32b6a8c1070ba1ea204a6e895e7ae0c4660f6ae61359006d7ae86aab6dbf5a350940dcdf209d46c7836be9f4621bb62bb91296f327f0bdf0bd2c97f32811ea12621a2654977b5a62b823d47a58e3abffa86d09a5a1f2c47957d2e0a2db8bb50e6dbe9a7b52bbf3624bbdedaca1aa08b549a5650758603732a6e66becbf0573ebcd4aed88180e2dd4d906310c7887cb2c31966bd6d1d0f748eaa547a029f043d18eab005459b60b926fa39d5d1e392dc1fe1cd009bf8a315b17405fdaa372bf7a9bb21930c4a8d82e46d5bf48bc54f33908d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136972);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/04");

  script_cve_id("CVE-2019-1697");
  script_bugtraq_id(108182);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn20985");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190501-asa-ftds-ldapdos");

  script_name(english:"Cisco Adaptive Security Appliance Software and Firepower Threat Defense Software Lightweight Directory Access Protocol Denial of Service Vulnerability (cisco-sa-20190501-asa-ftds-ldapdos)");
  script_summary(english:"Checks the version of Cisco Firepower Threat Defense Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense
Software is affected by a vulnerability in the implementation of the Lightweight
Directory Access Protocol (LDAP) feature in Cisco
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl", "cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:"Cisco Firepower Threat Defense Software");

vuln_ranges = [
  {'min_ver' : '6.2.1', 'fix_ver': '6.2.3.12'},
  {'min_ver' : '6.3.0', 'fix_ver' : '6.3.0.3'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn20985'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
