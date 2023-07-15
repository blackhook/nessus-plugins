#TRUSTED 91454c050352297fbbfedd97d3204a91acd2cd7191100003c8b604685091cb1ad82e7732f6ce3d75d9f67c659e06cc024b738850523c52ce35a81b84d7ea3c104182743fdba18ee20d565a385069d6fa7ec922275fcf1b344f3b2b498f42a3751de4004025402ee439c8e1b590a38948e3e56ad6ccca2e0c7ec7d76cd2d655657b3ab5e7aab215d6680ebd48c71334e1d6892da217707940cda0872e3e48ac706bc59169c83e63a94c588ed71229fb0df821571d925289aaab1921bef175eec06f77c936bbe907e874385940bf1ad37066b2af62c9fc3e9c1e5b0c36e845c75dbd204610fd31a0b9d484598ba1ccc92373fe5f47d199d4a76b07d8be21b0b318ff5499540a311a61bc0380b87f7c13aeae03783de8924730a3d39c5052706dbab925e36efb5e7dea30ec0f01c9a9f188998eb8be29229f21c7f0792042083806a6c5ed5189a3b74f9c0f3e6e164f9af92f7d80c1069071f8034367bba7c2325014308cdcf3c90d04e41baa9d0502901f0f8aa2d1591c659827c7364846c95a8ec1cec7c1ffcfe5e8db86a594c2b2e2ef5c7598466fced81a1ee7363328e05d7d922c55b671d1bdd2cb894892dc7f263316124dd32ecfcf6af874331ff46c7eb0989daaf25a46f6e8b5ca09d8ab75170be49b93a3e9f374df6af822564a497056c2aba8ea7d2f166a2182f2df843f24336a445055f9af41baca088ac7fe12c82c
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145555);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2021-1129");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu89555");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-RHp44vAC");
  script_xref(name:"IAVA", value:"2021-A-0050");

  script_name(english:"Cisco Web Security Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-RHp44vAC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a vulnerability in the
authentication for the general purpose APIs due to the absence of a secure authentication token requirement when
authenticating to the general purpose API. An unauthenticated, remote attacker can exploit this, by sending a crafted
API request, in order to obtain certain configuration information from an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-RHp44vAC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1adca350");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu89555");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu89555");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_ranges = [
  { 'min_ver' : '11.8' ,'fix_ver' : '12.5.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu89555',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
