#TRUSTED 3ebcff9bd59af4c8de13add293326a8b3ab9f081c645c7232cd38ff8ec797ffb7f2035d8a77b7711f7dad92ec1732f5e3c56d98b3288fc5d12632c5fce2160554f5548eedfb8f08acfe81e76c9109a8b7199851f1ee5ce12d9aeeb8d44d9e019486541e02926600ab86bff2c9e21a022aa99a6522b98881c58ecfe3db33ea06731adc953c9b7576c43ad0b2c0ddfebdf5967d667b7ae49b163e72a9930af7d877e28528ac10568565be04669284452df58a7fe1ce3c076d6290fab17aa13bf45def5a0687d5426150bab08ca03f78ee77c9772fb6ec82d27e58e3c81d963f811f0ce603d77815492c149bf2c8f52879da17566e0a59d8e0959a61dde1766f14cb1c435c6711916b72210981e9d53e9184c4a2108d47db335f81e8666f539c966cd2fbb81acc8f6c8de76435c50b0029184028420ab7fb2e04744bce2d496d011eda3adeaeeaf412c281f444508f048a6a1d30cbcf2554f832bbfa877f943e61e81087e3122e6452253e8f01def6b89ccc2388b6e053471ceb0c71fc73219f9811361b096ab4a41b7a0a0710dc9f32da6ad77cb7beb82349c9228a7357875228bce589ebc2987ef02f0d93b051e9aaa8fc068786a077e5e4dd36c92fb8bc7672c318c50780af9d3a1173430294cfd3ed88bb8c819ba2c075b833b1222a642bec9db23b856ba46b0e532ac5a72a0d2df07c53f69d8bd26149036a3037145d152ad
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146058);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/03");

  script_cve_id("CVE-2020-3456");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo94700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp75856");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fxosfcm-csrf-uhO4e5BZ");
  script_xref(name:"IAVA", value:"2020-A-0487");

  script_name(english:"Cisco FXOS Software Firepower Chassis Manager XSRF (cisco-sa-fxosfcm-csrf-uhO4e5BZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Extensible Operating System (FXOS) is affected by a cross-site
request forgery vulnerability. The vulnerability is due to insufficient CSRF protections for the FCM interface. An
unauthenticated, remote attacker can exploit this vulnerability by persuading a targeted user to click a malicious
link. A successful exploit can allow the attacker to send arbitrary requests that can take unauthorized actions on
behalf of the targeted user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fxosfcm-csrf-uhO4e5BZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9412e4c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo94700");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp75856");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvo94700, CSCvp75856");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}


include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(product_info['model'] !~ "^(41|93)[0-9]{2}")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0',  'fix_ver': '2.7.1.92' }
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo94700, CSCvp75856',
  'disable_caveat', TRUE,
  'xsrf'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
