#TRUSTED 0b02ee7a077d209b195abac61b90bf6940ea192211e19fcdb16fe6aa0c8c1b15add2892bb87e09272b28de61687c321206e3b1494a26198d42a01a8285351fcbf70d6e2cdafb88b0954b442a4d1784b2fb8b024d1e6c138ec32ea7aac2c5df961281c78adee71f178e99624347c309dc8d69b09a03851294a9e43b4eebb5a762b01453d8a0e5ec7ee1f5a1d87b821d46f9039cc4e6673e9c03291117bf28eb886065aa5de4440ad9ddaa45302bca8b5adaf5b7410a133e1a19ead1e265111e34c8f919ee1074a3da9ad9bbd8925fa9d032f76ac3317a635d0f4e38ef156936a52c928a6f954c23703b387fcaaa97dca8aaa81ef6208d1e418bcbbd9e1ee13da3cc793fc0f68da7f06c65d9d9ca6bd62d1c88ca5260c79ab93861aa4a397c7b33db6904d57500e77c02563e39a084d75b4a05af36d22ac51002c152ce34bc416d2e3a2e21fce1f853bbfeee386090f91a0993c11650a473ebe078c80ff18766ed15fae6610d39ba7ed2940cdd1cfddade51757011e89d9593859f1cb6546823b8739cd9c187f834d386a83e26265fe94284a92899ce7270e1820c0c4631cf6e4d900facceecc2ba1df14c55c73d00cc090549ee3cdbc2daad9885e12470d80542baf30092a5c82fd8c2b588a13acfd960c72fda3a00cefe1c04f1a19718bcbe2294f702e11b7d979f0da99142cb8f39fa564e1995cca4c4f74841ae4c36ee4028
#TRUST-RSA-SHA256 4340c36bf8623549dcf61dfdca9d072e769254804b052956def5689f94504036351f6af3381b1cf4d816322f8b93631c4422724571f20d8ac3b5ddaa880aa71054d935b39c68a4ae782acb0035a4902b95145a06ecf25b98cbe6d2e49a2c8cfb2777842afb2d12b7fc504bdab80d9b909daac083e7ca74aec7ae7db6052569c614a1e5ec6c0d821510743ae99043df502906053d90b921f84ffb9b12799496140c3fcf4f6beb0f071ebc2bb9bf829b5e3645a03dd6217442a683ed5f9d491af1c8e26d72df2c84d9e44cf6ce662564ca1a381279cc32fb78e83a2a19c6a3311e4a4c71a2368c2a32d94f925af27fff0dcf4e62e82f29c3b9550e878aac16b2cb5a632f202485ac16aea5f36d76060d83bdfb80db3d059bca0f4714fd4f4c1e1233fb5321e92a5acdacf63b2f8520471e8d9edeb6f09469bd323af47d27d01278f852b80864c166e4a442cc700fef8e3d69267d1b935099a348cff6547b673b1881b86e1dfc0a8eb65bafc5c29b46e39c510ba48a5dded3db819b0df62714e3050e576ab59a8cac3893b9098682c8860cdbefddfa9ddeea49b9026f5af21666aba1c5e7d93ee33d37e4567df4c8c9e215761a3b37ffc68274a6d314d29733462c8c575a258b212dad6692689f56e7fcf143c1c0afc1e5f1d09ee79c64fe43765083007ced73b13bd5d07fa6d3bf5bc3d0de8d5ad6077f50fd2aae59c2004a114c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177368);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/07");

  script_cve_id("CVE-2023-20192");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf28030");
  script_xref(name:"CISCO-SA", value:"cisco-sa-expressway-priv-esc-Ls2B9t7b");
  script_xref(name:"IAVA", value:"2023-A-0282");

  script_name(english:"Cisco Expressway Series / Cisco TelePresence VCS 14.x < 14.3.0 Privilege Escalation (cisco-sa-expressway-priv-esc-Ls2B9t7b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco Expressway Series or Cisco TelePresence Video Communication Server (VCS) running on the remote host is
14.x prior to 14.3.0. It is, therefore, affected by a privilege escalation vulnerability as described in the
cisco-sa-expressway-priv-esc-Ls2B9t7b advisory. Due to an incorrect implementation of user role permissions, a local
attacker with administrator read-only permissions can execute commands beyond the sphere of their intended access level,
including modifying system configuration parameters.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-expressway-priv-esc-Ls2B9t7b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b350287");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf28030");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf28030");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20192");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_video_communication_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_video_communication_server_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_video_communication_server_detect.nbin");
  script_require_keys("Cisco/TelePresence_VCS/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco TelePresence VCS');

var vuln_ranges = [{ 'min_ver':'14.0', 'fix_ver' : '14.3.0' }];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCvz54058',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
