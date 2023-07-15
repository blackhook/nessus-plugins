#TRUSTED 4ad713a9d0aea57531826d27188692e3c230ef4d6ad2fc6ea9c9bef2b7b98b2ab7c0c02379d2c7d90d6081298e0d989b926c6369afdf01e25d78c8d30e47bffb749506bf65ba52e23139eebfdc02d38b7e80c991659428de702ae4be524acf68f5e0a725cc1f4261c0d862f85092b54e8e36e0ef35d659a64a6084dc50cbd9170db11508c77a3d01d824c67ce67f651df3c9aea2ad443a148de66220d7b9bad1d81574273c644892f3bb880a7d38a108e9e2fd50195c8717d663732e5c711851ec7d0e4d396b6acbf5b1034ffc826ef31630a87385e249d4adea57d321002d856df34cedd772a3513a8897c8afd7df1427454bdd4d09166e7e1f78e6134e6c167221e2ac002abeee986c547fcd8fdb7e1606e0449e0ceb133418b9b9e1e3f5d8df99d4b317de81902856168e732fd48d516037ed21290aa5e730eaebb5037cbc793055347d2e6d4d6c159e826162084aa574854f0b534232bed5b829e97b4dc4ea232eafffde5716cbde215dcf62e10d5882e713b235162627bc3222342b000e7cd3564b4d2781d95b113673b2704186f489761bd07ceb1e1fc3189a1d12bd82b4a61aaecfba44394373cfbc045582f53a6ea443fe896cb80fb7793eb8cfe8c589809389110f8bcaf5bdcf68e91fe6b6645952d16555cf0b031a52d2ce1d22f3efefd99c631f57699b68d3bd55f12834942d05503d82f8986703e0724439f2fb
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166391);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/24");

  script_cve_id("CVE-2022-20653");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy63674");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-dos-MxZvGtgU");

  script_name(english:"Cisco Email Security Appliance DNS Verification DoS (cisco-sa-esa-dos-MxZvGtgU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by a vulnerability in the DNS-based
Authentication of Named Entities (DANE) email verification component that allows an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device. This vulnerability is due to insufficient error
handling in DNS name resolution by the affected software. An attacker could exploit this vulnerability by sending
specially formatted email messages that are processed by an affected device. A successful exploit could allow the
attacker to cause the device to become unreachable from management interfaces or to process additional email messages
for a period of time until the device recovers, resulting in a DoS condition. Continued attacks could cause the device
to become completely unavailable, resulting in a persistent DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-dos-MxZvGtgU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c030a86d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy63674");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy63674");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

# Not checking if DANE enabled
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'14.0.2.020'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvy63674',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
