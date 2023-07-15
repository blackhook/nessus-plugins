#TRUSTED 36673cb97f82ed34a211857e3f8ca3ce7315ee8b16726391c3985671d85ccce52c267b78a509012da764717eea150d6740a2a869359cab8ff0005de61ca1744410d6d975f27e2a228f676e6aa592bd76846a98474b8557724f97577a26b431d7e7400b38f4e4959a3b9ffaf760192e4c67a4348b289fed5f0f0b39443c9447f0eba91f386c93632cb3df6677ff8aa1254aacd89e1d24d84aa2ef7e52ef522ad6e1fd60ce93c4f3f650d969b8c5e319c2eb9dfdc84fc340e77ffcd2c9810935696bee06cb25876f0ff151fa7874de9ecac07c144489630341a6b9aaec657996e654ca247384082a92ff72e989cc94054f76994e8e560980a4961c26d28eb209c45a81adaf5eea7058ebb3c265341dd7b5baed4f52aefbf8dbf0a66fa08f497163df1a4427e2bf7e4efc08708a2c59950937522493b762acc638323e311e4fc2cd40678f8810a3beb5c33dcd1329cbc7fa3ea776eb46a5033dd36e6750876ce4cdd31409627c9021cac0ab5ff9a6f09bd45f0f4b507cc9653258e001718ef4bbacd6a064aeb2e6b6309ae8c1b5824ff937497c818a89fbb13777f8df946eacfb3da72ade9d4e1323955eb8b110a8363d39d8c24c8bd51af44d26f590b15b65a7f6dbed4348b3d1402b86d0e6091be1f730d4f80126c8ab5279131eb6c0a7c34e45bc2c3109d6470e3f694fdafaf86fee9f81bb3fdb99ce0d053e87711ef214097f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131288);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2019-15969");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp61143");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-wsa-xss");

  script_name(english:"Cisco Web Security Appliance Management Interface < 11.8.0-332 Cross-Site Scripting Vulnerability XSS ");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Web Security Appliance (WSA) is affected by a
cross-site scripting (XSS) vulnerability. Please see
the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-wsa-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d90682b4");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp61143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e86fe6fe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvp61143");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15969");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_ranges = [
  { 'min_ver' : '1.0', 'fix_ver' : '11.8.0.332'}
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvp61143',
  'disable_caveat', TRUE,
  'xss', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
