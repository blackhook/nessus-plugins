#TRUSTED 2a77e831cc7e0231e2deab222fdee3bd9e1cb5a800efe8d6b711ca50a29ca8c1dd9be3c02eb00c363979674ee6d14ec533e8d50f3fb7e85c393c71cd35c541ca6dfdcd9499f1512bb0ae491e43e8cd4a8496a9a9db69a1c4813e5296ddaf59d52026a83b683e6a891bddf491b75c5435bd8f263ed7bdc8a924e21b38e2559451df267d61bbf53bfe8bc8a52fe564c106a8a8e08280e350fb8a76566c98d815a990a736185dcd8880d51429e40b474bcd8bb44ede6c67727ed1846f1e290fd9403498ae02c4c5953ce03a5c6e7e813ebfe347d0c5b58831a4683678edc863c108f303594f8b3faadaa70b56cbc44a08f726d64dd9251de8537f6a76975320e6683d8f79eede8aee5494f0df4733912b78efce7c98be2b44ce9c535077e9c6e24c65e9888cf216de4ca72d63de821127fe3cea790ae1bb291b0ee01e9474d470374b888137590d189ce7690d8fe48998bee547acfbe515ef014abe5f4cf45a1e2fe6b818e2ea18ce2827089cee96d62857d14d5e1cc1abf294bd12495d2d90ebad98835a0f424e01facd9420d9daa78c5a8a3f53f9118853ee0cc796f6a643a15f5b280c267fea156f4924ec6003704cdf66c2c33be0856987f69bdad202b4d7173448afff6aa53f133945de9d433e8ab1e857c80a8580883da5a5a355729fae8f175559ec2c8dadd1fcd6095a7db26b68c20c0094f8196558b7fb693726f30b95
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138025);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/03");

  script_cve_id("CVE-2019-12676");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp49790");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-asa-ospf-lsa-dos");

  script_name(english:"Cisco Firepower Threat Defense Software OSPF LSA Packets Processing DoS (cisco-sa-20191002-asa-ospf-lsa-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Firepower Threat
Defense (FTD) software installed on the remote host is affected
by a vulnerability in the Open Shortest Path First (OSPF)
implementation due to incorrect processing of certain OSPF packets.
An unauthenticated, adjacent attacker can exploit this by sending a
series of crafted LSA type 11 OSPF packet to an affected device,
causing cause a reload of the affected device, resulting in a DoS.

Please see the included Cisco BID and Cisco Security Advisory for more
information and how to determine whether OSPF routing is configured.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-asa-ospf-lsa-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?192e9e54");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp49790");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp49790");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12676");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

# Advisory mentions a GUI config check - plugin is paranoid because it's not checking this
if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

vuln_ranges = [
  {'min_ver' : '0',  'fix_ver' : '6.2.3.15'},
  {'min_ver' : '6.3',  'fix_ver' : '6.3.0.4'},
  {'min_ver' : '6.4',  'fix_ver' : '6.4.0.4'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp49790'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
