#TRUSTED 0b125f30b895ee0aa1079f6ac6ec76c74363f3f404e88184fb336cb6ec1f5db0bf0d769cf4162d04a160272aed15ef7c07e86aeaff098d5ace08d4c6aa492f06aea00272f77ce4d2576e15de91a85cfb708991be206a2a6d6ad8b1ab297e4a01e7352afcfdadb7a34297905d328c84ebe20674e3cf0e5c4bee323491e464ae35202ca07a36b817aca149c95db5530930c2cd75035ac72a97c776c9def76aa62c1a5fecb7984f35a3f02acded0a7faaacc75fd199eab50eca09ea7836dd6f8169f8b578f6592d887c50434c64f20ddd843abf4dd5bcaf454cb01a6b3c54ed8b6acbd789cce36e041144f55f9df9ed665b7e49cf2969a0ebebd99ed322828e56647058a3fcee25ceb2b6632b967fe4711f5a093cee856d2e89767539eba560778544f9662103f5ec57004c8f1a8c4e28b572fb55425dbf8990a5a80ffd8bda1c77cf1cba76f4461135a0f12efb524eab068d77a290de26e0da4e75e839164dbfde4ad3a551e36492bd8ad1a3d6b4004057961c6c7841f141c974a23f87f3d81bec00c19a97ffa4d3c35f5487f53e567284654c12797ad1ab6da83a27f942590d93df69360e8bf6a02edfb6e1fe86266349edd9d3555d4cc8614526df0e9eac255a2eec0d2620c7a057a7278bd9b96d24627387ef55a928c37731173814f6eb4926cc0b1dd14139dc35e40a103f27ef781586b0e49c9f97ba3aabc03b0492f299bf
#TRUST-RSA-SHA256 10f40cc2bb3e68304a16670b4812a3c9dfca25ff1ce310ddee51d3244571210d0747817b3bee62f6e18a1208fb540d411a2501d16be9b68a5a45608094fd532f80cc73545ea38416a8fd4a57733b3f2a3ba66f56847d4da44ba225b9705bc23a2e4a31bf7a84b1790b93444f22390c4ca6cea0a549a9ee005ff8f13afe4b2c53e45a3df6ef469c22a0a0fb91a1303459e510410a9a2ec76e1ca3671916084cc164cb7e411c78cbf74a97c974ba4e29b52a06694c909fb5d882c99ebdcc0c818be1514f4a24c9f528a78dfa469781fe091f71143757ee92c9f31520365c013d2fff08e75f48de3f0cb6f929c3cf67d4e512281af3dd09d63ffe7ec038c9580059849f7d34b18e22bffa338238515c096248a89d97de742f3315d76ea0acf99484a84b9e903d8c512877f7954a5ffca3614169440426a84f69b311d15e30e2babd069eeb67eacddf5ee3faaebbb2f701706933a57db3b5ab1501192c3d7d7942334db61f61d1afded6d2cb837fd7e7b2410eb316cad192ab951a8b7d3ea59d006d9237662a937b8522dd06499526732b02b05d1a569a116306eb687cefe5a068673e9021f7d5a4383acac5823cebbd84b4e98aa693b6464eb6951a1c9468bd06b2db0542fc30839c455a20c5af518dd62c8c5bf3a7e48b845b588c9c1d5f496edb9c8933aabb07f6875fc0d93f57764f7347232229fd233a3bfc309c82daf1b788
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166905);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/28");

  script_cve_id("CVE-2022-20772");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz24026");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa84908");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ESA-HTTP-Inject-nvsycUmR");
  script_xref(name:"IAVA", value:"2022-A-0463");

  script_name(english:"Cisco Email Security Appliance HTTP Response Header Injection (cisco-sa-ESA-HTTP-Inject-nvsycUmR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by a vulnerability due to a failure
to sanitize input values. An unauthenticated, remote attacker can exploit this, by injecting malicious HTTP headers, in
order to conduct an HTTP response splitting attack.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ESA-HTTP-Inject-nvsycUmR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc1d0d7c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz24026");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa84908");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz24026, CSCwa84908");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20772");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(113);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  { 'min_ver' : '13.5.1', 'fix_ver' : '14.0.3.015' }, # no versions between 13.5.1 and 14
  { 'min_ver' : '14.1', 'fix_ver' : '14.2.1.015' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz24026, CSCwa84908',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);

