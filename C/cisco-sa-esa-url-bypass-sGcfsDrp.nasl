#TRUSTED 187f3a9cc12bf642f69a506f730ba5cf6cc2f52049b18dcb344a4b7c68ea9e87231f41af43a6b5ce64b353711654bd14dc1280b67e80543d243757635186fb6059dfb3028be2a5c871c53b3b67fbcd64211e9ab858af21d63cea0bcdcfdc707936a91c8ab58a065d4a20a6f3f3868ff26646f7682a532d93d9d400cd2d703d97a2402d003fb4444d5120a2bdc955a5c698868df2cb2ddbd846414031fdea17e601b56a00ce2fdaf51a4f21901b0a31e8fbb2bf9327451aa1e28ce5a0396e7404c483e0ef4a016b53bffc47ced3d45660222068cbe9e97f1e4fcd6552049e7d25a25892ad779daa3a86408f8313516a67c445d7eb8143144d982cefcde5f1a6afefd3e204e0f998412513c1742a546189233e87dd9ac85da18383668c2034c3e28528e27d8ccfd56f8f5029c27bc897ac5a796852b66909d42a2241d6d5e03733f4a205a6772b09afbd61d53820d218720b00c287a093fbf7dac25742e89f6be7b232a69bf467cbc720baa0fc66e5abc9251e9878e1775e99bc397b2434b5ba46989f086d6386409c469e30d42f327b637aaaab0e74b9a866473ad01354883b0d5bd5b0828b9621be9e8f49c3ed690d9eefffb14f74f66e4bc08500b5015a7314b704e84ed1d366ce065b6b082b89a530cb4fae8104f9e8addd5550308039bd6e220469eb9b6cf2e289008ae71aca476fc0bc308725673bd5ee10209545263d22
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153943);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/20");

  script_cve_id("CVE-2021-1534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx60178");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-url-bypass-sGcfsDrp");
  script_xref(name:"IAVA", value:"2021-A-0454-S");

  script_name(english:"Cisco Email Security Appliance URL Filtering Bypass (cisco-sa-esa-url-bypass-sGcfsDrp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance URL Filtering Bypass is affected by a URL
filtering bypass vulnerability. The vulnerability exists in the antispam protection mechanisms due to improper
processing of URLs. An unauthenticated, remote attacker can exploit this, by crafting a URL in a particular way, to
bypass the URL reputation filters. This could allow malicious URLs to pass through the device.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-url-bypass-sGcfsDrp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f3f84bb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx60178");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx60178");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0.1' }];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvx60178',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
