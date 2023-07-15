#TRUSTED 787c514b8e1766f05186c4b06606bfc4864f2969d8cc8a6a1e3ab7a19d76cac465f195415335f506dc49902867befac0e6c5467f47d09d63674975ab55b7565795077325637627fdfee763c788547cada4cf1148021009744561eea0b6d939d398d1e3dd1a99fc3031b725a32bb70cce7c37122129d8ef19f023ddf57493ed280dd7e7ec4e37e11557c205f9b94e8b546f2f9bb993c1cf3ba75d3fbcb7b2d3ce832f6588e514c84a881742c85a318a1a57b6e86614ea86312ad4bdcf4d1a0865a7b0c7f9c594c7870656ed78237e9eb53f80064ce84ec23f093270500ecc27483b44706335af2cd685ac0fc33fce247bf7dcb137d555777f88fe508dec46e451a07b2f7e343748877d222462591afcb064113a0f41de556e2b482ed3496beefc0719dbfaf42bc62fb4cda8f9a844015f385533247b97b790844b817f29c1977c7464421176e6bb9512b532e2a322b8ff267d0c2586ce9f846083656c734acf2c2c60005cf310aa4c280c1c5b42935e13a4b89b37bb35822c02972409449c83e54e5fc22f5f3d393ced682f8189edb2c8494ddaca9f5c34da8e02afd2d5cd1b4a3bfd85ab2c93d1189f9fe94776832fd663c6f81d61bb3df55fc8ed07bfa7a34c8fb290007125a67df66bdbb39a4d1f4e6da1dc31fd2b69dc28877f4bd7c5546a495b68ed2a55e312d86e855df79f8a8e0113564789ee1abd282ca1478581e15f
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149844);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-1516");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98333");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98422");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03505");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw04276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw35465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-gY2AEz2H");
  script_xref(name:"IAVA", value:"2021-A-0244");

  script_name(english:"Cisco Email Security Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-gY2AEz2H)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Email Security Appliance 
(ESA) could allow an authenticated, remote attacker to access sensitive information on an affected device. The 
vulnerability exists because confidential information is included in HTTP requests that are exchanged between the user 
and the device. An attacker could exploit this vulnerability by looking at the raw HTTP requests that are sent to the 
interface. A successful exploit could allow the attacker to obtain some of the passwords that are configured throughout
the interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-gY2AEz2H
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?156a645c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98333");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98379");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98422");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03505");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw04276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw35465");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401,
CSCvv98422, CSCvv98448, CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(540);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401, CSCvv98422, CSCvv98448, 
CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
