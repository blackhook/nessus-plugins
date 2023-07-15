#TRUSTED 1dddae677108dd390eb07d23594445bd23a78434392259fce05193ae36bc01799c7b64a74b1df6e1974014b818ed0e9876e690a9fca8e8e1d57b2fe5f362149b5f089e402664ea43f1b96cf80c57d871df8ec2b01d6727322985df9e962fc370509f7c89c0e01b0d95f1c432086d6163b575015b2ab6e97cc348aec042fb00f0cce52b644eca419216dabbab7f33654adde998f6e70c92c7750d295b862f0e03c35864907cc6d191a056b3418b8c472bba1c788cebaa803da003f3869b2801eab46cb5b03e1218c38fa1fdf30d6880c77706b44842617c964d0fff284d103cdb28cd9737b86b5d91b21d5c8962f8a83f3f4608107ad4fab03c6abb9fadcb49581d651d497d5db88a87d251cc945e93467b7e5ba28fe1c06ca922f11922d9b42da752de06befe16b1283eec1a43380ac8a5c7db6cee712ddcd6ad1aeec22f2408a2c81b6d4a64605ab125d026964a0a26f469b7eb26b5c7244987282829fcc195ab7af7326446efd736ecdba013229cd2c711083ae17a04c880acd26031c27b419c84339c96a929670b45352b23fc7637b1a72bfffcdc5e24b163d31d33a100963d83742af3bfa702f941da58bb0928f01e2814ca47e67385c8b522ad4fa63478e9e55a076611ba91a721df2f0e706470700bf52fe52282411e122972b3cce759004880a804f474d3ac12ac7d12712b7364241ae8abe44e318b46481b154b50d1
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145706);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2021-1302", "CVE-2021-1304", "CVE-2021-1305");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi59734");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs11283");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28377");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-abyp-TnGFHrS");
  script_xref(name:"IAVA", value:"2021-A-0045");

  script_name(english:"Cisco SD-WAN vManage Authorization Bypass (cisco-sa-sdwan-abyp-TnGFHrS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by multiple authorization bypass
vulnerabilities:

  - An authorization bypass vulnerability exists in the web-based management interface due to insufficient
    authorization checks. An authenticated, remote attacker can exploit this, by sending crafted HTTP requests
    to the web-based management interface of an affected system, to bypass authorization and access vManage
    tenants they are not authorized to connect to. (CVE-2021-1302)

  - An authorization bypass vulnerability exists in the web-based management interface SSH console due to
    insufficient authorization checks. An authenticated, remote attacker can exploit this, by logging into the
    web-based management interface and using the SSH console feature, to access sensitive information that
    allows the attacker to carry out further attacks. (CVE-2021-1304)

  - An authorization bypass vulnerability exists in the web-based management interface due to insufficient
    authorization checks. An authenticated, remote attacker can exploit this, by logging into the web-based
    management interface with a low-privileged user account, to access information such as logs,
    configurations, and device information that they are not authorized to view. (CVE-2021-1305)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-abyp-TnGFHrS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b139de4e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi59734");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs11283");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28377");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi59734, CSCvs11283, and CSCvu28377.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0',    'fix_ver':'20.3.2' },
  { 'min_ver':'20.4', 'fix_ver':'20.4.1' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi59734, CSCvs11283, CSCvu28377',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
