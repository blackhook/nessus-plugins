#TRUSTED 7cedd1aae5d57224c25728834f2e1287d266997de28aea9d9a186da459891a783592a3f8112bfb5d4dc10b1b62b25412c2fdb67eed682b2a1a29a3fabb88b4c68ad73a03b21c0d9726939d156fd5335e1aec006b6ae8d6be6d9239b56c949209c13134eb820d6efd3965711486891d48b7031c289a1d09ff597f88c643bccf6a85511f5c47dbd3e1bc955fbb55fb6d060444ce3335bc6443f0563e2244db4362671de21a51020a622297d142f5da3216346a2809cc66adaddc7832b948656bd4ed1d8948c344abbab63a4facc5fecb8167c26846016831404ce1b6bff6cd822f39ee6d5ee1c775efd16070f5328ac5225e610ade85773157bdea166fcc07a4c290828e26d5a96cd49229ac45816df83d9fd3a75f95f2e3e7e3a99292c991658cbaa33add788fc87e4b8746f509fa4d5db726a6031835f70fc939f196873478dfe32f1558248fc1a0dc6d78adc046282c86962edcac4e2d8e859d5db616dae652f002659e97efa028279d59f7b9738408555d3d84f63186f060aae8a9c91048a02839c3d2ccf472d0487965d4135582be20189c09eefd81011a14a3f84fb0cdf725a1779c9d9f8bcdeea770a3b93c4176aeecf19b597dfb811d4ad9ad593fe61cf4250fb22469a4727a7de2a776a6aaac4e6dd1a9c4d21c7297e3c96a1d3655c8e580b990ded63db9ade1c50f9bac2a3eb69be934928f58e39947d1ff220abcf2
#TRUST-RSA-SHA256 6d1e5bf092ea539b93f299a60497f994ac8b28365eec0d3d236d8a0bd2ac3a4c354e19bd5f0209b686fe0b40a54a20b8074b38c63a0a6f389eae5353abb939b78db9d19e34b8b202e1bd9e63c2d791462beca4be567a8173845dec8e4cd30ea02442bc599cea52b03d1f7b2b9045aa60149b73a754a31fded69464bbab7976c6b23ac6944daae5751509850a38d1749d5fb85492d8e87f045e42c0befaae7c78f3e1bc7b45496b77fc4de163813d2acc096424e23f535604c0b594e718888aa3a5b33a8220846b2982e6b822a2fcf0b8331b9ec1f521d226efe3eedd9e74bb47071b5aa028e5c8fc50891cb0dc0f136a0d35b5ca40513e315f4ccb55c0ef787ba474f7348ef32c4c7f64877100824e66f88f20ef1ceb492eb5a0e36f90372ca14fcf26ce9a5106c43b7c561344a78e92c12c25a5b4ef6fb82daf19c28a2af4858aa23584fc791b3cf398ec56c5a70e80153a9f4b0f4be7ce1523b7ba71cce74df6f826839078b1f5d70a963167e42dd17a034751724043c824253e438ea251454afca4e5af6e011fdf185f9d9513c8fe9c53c28cad7babe5aff8c7cbef56195a4ef570ab0e4e7f669bbed5342b676186f8b4a19190359d1bebd8a09e791c868657076045a0e5af411049d3a84a5527210a8dc201c9cbfdca5059d68716500c688d066fb9349d445b4e4256e0b3650462ae09dc89f86a6055d07294f530086e3a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154878);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2021-34706");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy75191");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xxe-inj-V4VSjEsX");
  script_xref(name:"IAVA", value:"2021-A-0455-S");

  script_name(english:"Cisco Identity Services Engine XML External Entity Injection (cisco-sa-ise-xxe-inj-V4VSjEsX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by an XML external entity (XXE) 
vulnerability due to an incorrectly configured XML parser accepting XML external entities from an untrusted source. 
An authenticated, remote attacker can exploit this, via specially crafted XML data, to disclose sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xxe-inj-V4VSjEsX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64acb660");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy75191");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy75191");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

# From advisory:
# At the time of publication, the fix that addresses this vulnerability is ready 
# but not yet available through cisco.com
# Hot patches can be requested from support also.
if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var vuln_ranges = [
  {'min_ver':'2.6.0.0', 'fix_ver':'2.6.0.156'},
  {'min_ver':'2.7.0.0', 'fix_ver':'2.7.0.356'},
  {'min_ver':'3.0.0.0', 'fix_ver':'3.0.0.458'},
  {'min_ver':'3.1.0.0', 'fix_ver':'3.1.0.518'},
  {'min_ver':'3.2.0.0', 'fix_ver':'3.2.0.542'}
];

var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0\.($|[1-9][0-9]*)")
  required_patch = '11';
else if (product_info['version'] =~ "^2\.7\.0\.($|[1-9][0-9]*)")
  required_patch = '6';
else if (product_info['version'] =~ "^3\.0\.0\.($|[1-9][0-9]*)")
  required_patch = '5';
else if (product_info['version'] =~ "^3\.1\.0\.($|[1-9][0-9]*)")
  required_patch = '1';

var reporting = make_array(
  'port'           , 0,
  'severity'       , SECURITY_WARNING,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvy75191',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

