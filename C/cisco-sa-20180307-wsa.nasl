#TRUSTED 4b80a92ea770fc43c224fcff88483c0df30e576343b1d1da1b3bf38aaf6520ef305bb1aa9024c556eaf7251f50657f25edf9b92e5f426e7f8f193a2a111e5efee87628c6cd520e16ceb549c8334ee3de717842c059b1ded8d1658fd1ef1244f984991f6487c94d2c781030b4aff6793427a0cd950e559a66fc30462d15dfc342ead87136bebeb2643bb310ef62ab8a798841fc86c04a55ac23295b762ef7f559a2266dfbb51dd4555495984eeba93a9b1cbad09ffea8ac7500dae5c06d0842685a76ea9598e90e6d39158126751a77d97e03a7fb3e8d8da7dac179da46eb3666114f9447b42f1df3fd6cd658122023751f1a0d0c1ae669d7c662b2b1d83f0abfb0f00df0191008d5e3d62c1c545d484f38a1a9273782ae9f6c6133ffd80122ef8a27b479da360e5e89ea04aa2915e81fa5fc05415e352c19e148835f37cbef8af53c661de0a4110bbe19a3a80d483d7c2a773edfdbc99b387d84bb6c2870ee2f18a0a3a0cc01ba65531f38486e9b4fbaf39718cf9575c119b0fd1572beef10748cc71ad949f62ee1b8768c990fd59ba71f1d4c8909e72349e57127c4ed62166d124c7105cd55ac7b3a55aea519f54fa5dde97b398f593464c0cd88ca77c4ee6cd1a39b15b4db923baf784c99346ddc066b184fc4030a98f18b4c93ea345d782d8c5ae33f71af58aaab2accd375db66f6c0877c5e0ce218b064f43528c3dc9b36
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108404);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2018-0087");
  script_bugtraq_id(103407);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf74281");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-wsa");

  script_name(english:"Cisco Web Security Appliance FTP Authentication Bypass Vulnerability");
  script_summary(english:"Checks the Cisco Web Security Appliance (WSA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Web Security
Appliance (WSA) device is affected by a FTP authentication bypass
vulnerability, due to inccorect validation of credentials. A remote
attacker could potentially log into the FTP server without a valid
password.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-wsa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e607a8a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf74281");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version 10.5.2-042.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0087");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_list = [
  {'min_ver' : '10.5.1.0',  'fix_ver' : '10.5.2.042'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['AsyncOS FTP'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'fix'   , '10.5.2-042'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_list
);
