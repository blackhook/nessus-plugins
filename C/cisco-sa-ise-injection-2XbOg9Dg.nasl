#TRUSTED 6c83d8f132d49d1385bc6865e22c8a25cea79fe06d7f6e51c34ca8c26a4232b2ad02f656f84764acce6fc8b6b1dc747a5e190161c5703fb2b2f06ba4c6859115afb96cbece0900befb70cf285b6e948824b74b2ee2f2d962c36b98e09dc1f812aa4521afe8b3194ab466cebd10df38cad4733ccb5a65dc82d2eb122f8afa5f713711120bd95ddc19232326d0590e339956bf37af42a520d8b950a6b71e12a47224b5aa9d85bf42822e68dc8fc459f03e2671d2bb74d8cd2e74a131e9bb6ffedeb451797f25fb6d383d1bf3b13d6dfcbc91be6690b2878bc890aa53f34c17cfc6009af8f5ff07ac86d223c287a5bc12a1bb233a6df40b1e4227a898fd789c56e9e50b69cebdc8f58abb3dce68bf0872d53fa139c260da80334f6d4f85ef53ed28ff6cefca7a6939b8592caffc6350ffaf74c88839f3a9aec3a6e2e26969aed369002d18f6337b4b63cda450ace9a6480736faecfc6de6de93afca53ab3e21558c877cf5f5ea3f1843d85a317bb13423093575bacb080dae86c9bbd499af4ce6a52dacfaa7cfda2dc5defcaab44016ae68247b5bc22a3ef28fd23b71c6298c3e70938adf376d1fbbdae01ceb5fa6c001b5c2d90e7a473beb8c02e371cf325adbd30ce1334f658f626a708fa523e9751a5feb72a7d92e94a47d63d39ad3ea6887047524d0188f15315df2868f8b1c8eba7cfa726f277bc4eb3eee66a660b3ccba91
#TRUST-RSA-SHA256 9e86af07c3b6e928b0243d9c99d4915e843e1b976944012d71199c839a59df601655561066db582ce819fd3403b8abdee1a269eac0dfd6652407ebf632c094a764cb495567012aeb0024e947c6c6708b54855594cc5942b0f1133dcce8025c2f4c21de442c7dae7c5680e997c763dfca132f156c8256c8f5283e67fdabfe7869bc256e641e3b0ed98c38cfe9270fc829cf9ee65e5bf01285088b6440ceee5a9a92253dcfcce141cf8cadc6c963b32c65775653d739709dc0b1c72508b6ab17d46e3fa0430d7f6d2e41d57d7ea9937d2c6411b14a2674ced3c53f90897e66eba9d23e6feb6b600cee1a285a9a773ae0e469c44850bad864a7c4548996abd768061c7a47e543c7d64ce08429f36b984b1281401dae50a8148c3f262e6a48b23c2d3925db581f072dab25366c80e76883820c12a95f04a0457c9c7e0e8de52923f6962e86e38e2b360aca513c8c97c81803c765d14be2127f81e41c6b1d395bba10308a749341d7f7bbd737fad6d4e58063ed17f4171804d5ec928764cd85233f4861925c6ba6808af7ae9a3e00a615bc8646ab6029f8d9db9faea0ddc15d0d2295fcb229b5b89e8fe57a326436c49b47748a8d6845409bad6a6f1e2c13d7359e79bdc2bcb0b3bdfde834479dec7ed6b6642e2ceadc0c351171cd5867c9d1ae67a2d4af8fb8ff6d98dabd7f1685a9d108c3f902b20f5dd5ecd9b8cf2c9df784dd6e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173952);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2023-20152", "CVE-2023-20153");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd07349");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd30038");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-injection-2XbOg9Dg");
  script_xref(name:"IAVA", value:"2023-A-0065");

  script_name(english:"Cisco Identity Services Engine Command Injection Vulnerabilities (cisco-sa-ise-injection-2XbOg9Dg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple command injection
vulnerabilities. Multiple vulnerabilities in specific Cisco Identity Services Engine (ISE) CLI commands could allow an
authenticated, local attacker to perform command injection attacks on the underlying operating system and elevate
privileges to root. To exploit these vulnerabilities, an attacker must have valid Administrator privileges on the
affected device. These vulnerabilities are due to insufficient validation of user-supplied input. An attacker could
exploit these vulnerabilities by submitting a crafted CLI command. A successful exploit could allow the attacker to
elevate privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-injection-2XbOg9Dg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?570a0f99");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07349");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd30038");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd07349, CSCwd30038");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20152");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is own  ed by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd07349, CSCwd30038',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:'1'
);
