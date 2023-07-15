#TRUSTED 176d37080841fe69e72852e7d42d3e7566e5ad76ad88c6f02c78fa9e3eb9044e5faa5633fccb0ed5b150496cd42f2a79c033d028d277f6738476c55f9fafd4248abeb0ab00366ce7ed930b7dfe685f9090d268a99dd341c5aec1bd005ed88eca1701b7488962f34ab0be279b2af684df25570300de930e76beb263fff3ba95564e19955626588132fee18c3e4733f4a1d4b726a9d3ed73822ca029bb05f2afaf8d2ffbe318d48697596871a24252ab6c29506090f3fdc50416a3f62e0970c3935fad5006b9a5d8f4405915c82f54c07b3e2550a42a13da9449bde3dcc0086494e8925ea0c0122b6fa57ed58fe42e38c062f101d7ee88a07e7bc98433c8f87f0f9a878b1e2fe09687c9138f049e711231fa08425c4f97689178f79a788dc518a9d59ede8b40d921b1ea70b8b8d5a40c658c866776a1b8d8ca1f5bfbcf7c56d29701a2fe2102a234f28deb537da49f25fd160aa373ab772a5e9706e07fac58ea3510333d4eef52d201ad28ee2ab11f940a1af164fe46aeffd473f064d0709f92ee1bf89e066e832cac66c76e034d84e3fb6528572658479f2d043f3132fe4da860ae05c4281b8f33dc5524fb3829302e4b062bc2e61e04021bf7f3da7077c80f70f416934e1f16e02643d144613d02236571510b324fb2f3efc5af4892526138f7e89cf84f9dc4ff93e7037aad4afd0ff4c077d549613009618e565b391a5d09e9
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147653);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/12");

  script_cve_id("CVE-2019-16002");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo19118");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-vman-csrf");

  script_name(english:"Cisco SD-WAN Solution vManage Cross-Site Request Forgery (cisco-sa-20191120-vman-csrf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"The version of Cisco SD-WAN Solution vManage installed on the remote host is affected by a vulnerability as referenced
in the cisco-sa-20191120-vman-csrf advisory, as follows:

  - A vulnerability in the vManage web-based UI (web UI) of the Cisco SD-WAN Solution could allow an
    unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected
    system. The vulnerability is due to insufficient CSRF protections for the web UI on an affected instance
    of vManage. An attacker could exploit this vulnerability by persuading a user to follow a malicious link.
    A successful exploit could allow the attacker to perform arbitrary actions with the privilege level of the
    affected user. (CVE-2019-16002)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-vman-csrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81d08a45");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo19118");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo19118");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16002");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
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
    {'min_ver': '0.0','fix_ver': '19.2.0.0'}
];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvo19118',
  'version'  , product_info['version'],
  'disable_caveat', TRUE,
  'xsrf'     , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
