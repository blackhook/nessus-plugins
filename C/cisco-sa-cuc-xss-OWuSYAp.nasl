#TRUSTED 372e60b4f49e52fe75d0a93d1260ede285f9f5a8ef69e047b9f603b0b6dc7b7a318792287c55878924d574fe5846f7516f0253fa29f81aa672986bba790d59af786c78256df5ae89824205ac2780dbd35e8dd03259f12a12fa5a6743dae7080eb4f8d0e1d70ffd804fb73370ce0b77b0347565b94670e2b6a27a3a3600fc1e2b4ff9b8f8fd6fa4eb0bfc074c538e30f4436b2eee3683bc9e28227ec018f7ec50dc81fb6bfa9539a001a34cb5881aa09b719a80fbe97656143a9928a9000a46e0ce1083cad383411b8748e661f64122f1c65bd2363c85b266a9ca00f3d0e197fbaf3661e878bee129fa2d147337f3960b2a261afc280c389403f62143daf0b1c6ccebe1b3e99f61ba881c72c477cc0e9bb1582555fe301c71254f862294d0bc8f86c006b43c964495ecfe58588a92666120c7167e1f06feef2ee094d69f616854bd1bfde5dff9e89f86646bbab324fd26a7faa3b3acb77cb0f244dd70c2781d42bcfaec3a965fdad6e0d72ee63e135ccc5ab19a5c1a051c99698af5d1768d7e6b6b74b80aa44546cd6e22db2a8c3d668cab9f908bd5e77b0a048670523ca28cfc2027176b4f2daa31033f01501e2c3bf5275dfa63cdbf196079300d6fe109de2261258e4ec1361697b54ed3eae14014ef60db3761e443e247382f5fd4c8ad05547ea3a986b0f9ff41dd7b61df7f89c212d0c88f2750ace011f70a1db312d0b660
#TRUST-RSA-SHA256 b2720d3c7de45410a29ccbccc8932cd7cb4578778d20bdb754555c0bf50047504a0022678e940c8ae9be5db4027213e62fc0f656ffbdd6f9f75b8937f4395523c36cd587e4e55da8609284fbea80be5f25bbe44b103366bb20d31f7d178dbf90851f15bc84a23b6e324a3ee2f4d99dbc2044d42098bd25ac0cfe1ad8711703f77cab7964b0db29da4ca5ccd9a430178d2a8a592ee01bece7dbcaf2d8007417b67876fa365e2939fad898302f69a73e788756f7e00f80bb53b141e1617c50d975eabf9bdedb9411142db64e92ca4a12edb40f57f7ea1b8c623b0a41087aab94a5579f33da3c274a56a17a8197039f23e724d6ca9f605d4f05af59149f269655cd336e233babb842b756b6658009f9f9e0f00598132dadb887a770063b55c5f5e8267948a2adf174d76de6a0de481d5a3451595c6db0e2497185be53b3f43022e4320e2c66b4140890a7b238a59b8793bbe3d41f60b3c59d5c5b8e2045a6defd46f0e2b24abaa999fd88396215b711db281cd3e92a128e1c366d6a78a3424920f3349aa3417d3b11a1ea6eec4dbe24a764bea6be0951218bb8080af9694cd9a4411ce796d91dc1e72eabbba4b83a591e44b9a9ff5435942c633627c6fa1ffed999521461a53fb99c0dd69f13f3da5f7edc0418706bcf6e9232362c38c580366a59fda320d1a89aa89aa92507963f779fd7a452243933766ffde310648d0fad5e9a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139228);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2020-3282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs59653");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-cuc-imp-xss-OWuSYAp");
  script_xref(name:"IAVA", value:"2020-A-0297-S");

  script_name(english:"Cisco Unity Connection Cross-Site Scripting (cisco-sa-cucm-cuc-imp-xss-OWuSYAp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unity Connection is affected by a Cross-Site Scripting
vulnerabilities. An remote attacker could exploit this vulnerability by inserting malicious data into a specific data
field in the web interface. A successful exploit could allow the attacker to execute arbitrary script code in the
context of the affected interface or access sensitive browser-based information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-cuc-imp-xss-OWuSYAp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef22b106");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs59653");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvs59653");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

# At the time of publication, Cisco Unified Connection 10.5(2)SU10 and Cisco Unified
# Connection 11.5(1)SU8 contained the fix for this vulnerability.
var constraints = [
  { 'min_version' : '12.5', 'max_version' : '12.5.9.99999.99', 'fixed_display' : 'Please see advisory' },
  { 'min_version' : '12.0', 'max_version' : '12.0.9.99999.99', 'fixed_display' : 'Please see advisory' },
  { 'min_version' : '11.5', 'fixed_version' : '11.5.1.18900.97', 'fixed_display' : '11.5(1)SU8' },
  { 'min_version' : '10.5', 'fixed_version' : '10.5.2.22900.12', 'fixed_display' : '10.5(2)SU10' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);