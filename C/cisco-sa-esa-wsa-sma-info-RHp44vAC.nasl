#TRUSTED 9aa26c5895cb123e856660c1380d297bda9753fd78972497f0221042495b61cc797b63ccaaf68b5e3f22d7bd5735db859a51efe0b91ff49000dec6568dd91e5d93bea665889119d7a5b471d64e9a85fa1296cdf0f02715742674aa8f3fd256dfc8848f4e4b232773700661d04b0ece1a9d458035ce58c1a1a45e35bb43748fd31a7b662031cff627869a38586f87fc0038c045a592e066cb6107281cf381f19724a729df9ab1e58b56752e3c84a9a76feace58e306c3c39fe3e3fdc7449a51ac89d73e29b22dfcb8b0738be6ed54edbba2aaaaebc0847fe0494763bd1885bde2f285c865866c9f4ba9124f744dd17840126c6c2ebf8d5ed244964556914995ece3a4f16e6441d7932f3b8d3f3a080a4a6710ca39f5d97247eb566e0b08c22c4e69b682b6559463a7fe1de105ea34e2ecc0c03592bbf1f9342ab0a081fdf332b635ed51e3e9a4ace717d6c83afee25702027155bcea080f816d5b9b9fef51ea7404f62e0bf974e760afb8bc6256b22485133295ddcd505a9c1b93cc2fb682cc14cc282f70f3f963adfd86687a8562469d48ef6e1f606d9f2c71a6b8d072fcb02320380949e5bf60366490d33c6af3ca6ea44a4182157346e312e93bc4b9414da62c7e907c155bebe729b69b84c47bb414934d7b95d54a99bcff6acd89924fd58aa3b2ef81ba147a3465b46616995950ad7a7e20fb8456c6f199809cc3470bad7b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145553);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2021-1129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu93199");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-RHp44vAC");
  script_xref(name:"IAVA", value:"2021-A-0050");

  script_name(english:"Cisco Email Security Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-RHp44vAC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a vulnerability in the
authentication for the general purpose APIs due to the absence of a secure authentication token requirement when
authenticating to the general purpose API. An unauthenticated, remote attacker can exploit this, by sending a crafted
API request, in order to obtain certain configuration information from an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-RHp44vAC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1adca350");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu93199");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu93199");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1129");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(201);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [{ 'min_ver' : '13.0', 'fix_ver' : '13.5.2' }];

reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvu93199',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
