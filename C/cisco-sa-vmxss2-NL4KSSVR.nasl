#TRUSTED 2a4bf2f84ff58a7787be829530131c1c81f6beea56c57f78960ed8fd87b108a27eab20de0bf0f0dda629277c7991c27fa560f12a69ed96b2b0ab79cca07562488db684cadd9a68df03b1795bcfda505aa531dc714865bd6e2b935de323593d9d2f5476c564484b6dffc75aad0852551bb3be367ed7431238bba43606bcd8efeca7e137766350d64536c38e7e31e0f205b6d2df9283323625f87c266575831b4c0934fdc0541db58e2e3a1f00a2d8b4160213a7763ebbebdbbce5ad36511cd323655b2d119f63b2926bd07af33e71cd59c310c6672261c7c133066d74a1369d84aa2197e326153529af2ece448011ac5caf6a044e1951567a89d3a2b19996ca616b508ca5a23e1234bfad8e7d5f9b16b4387f066a219bb584f24d5cf83d76e395b45e8d62c162a2831514cbd245f971710a1065c0131f99c14b2434bed90264408f0a349a87720bda4d56acf1fece250fae5f71c32d1a4b7e454b6b1fb79e1df005ef0fae6cbc12190664a27e07a582dd61ab14b8736882afb6f8bbc56219c932fc83fe19726862ac77000ccaa908e0d318acca689973821918e696f2ccae2f078178d7a9203655c69dd0dffc92a9707804e82fff40b36915161013946fbe1b8727c0ba293671d23db98247b9b6bfc7aac1dbacd06e798864dfe194e8ca1a228384963368c945d5b752ed7c3b08e1be682f6763a7c155146451b77fbe3a049ad8
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145557);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/02");

  script_cve_id("CVE-2020-3579");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv03478");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmxss2-NL4KSSVR");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software XSS (cisco-sa-vmxss2-NL4KSSVR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-vmxss2-NL4KSSVR)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a cross-site scripting (XSS) vulnerability
due to the web-based management interface not properly validating user-supplied input. An unauthenticated, remote
attacker can exploit this, by persuading a user to click a crafted link, to execute arbitrary script code in the context
of the interface or access sensitive, browser-based information.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmxss2-NL4KSSVR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae47cbf3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv03478");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv03478.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3579");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

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
  { 'min_ver':'0', 'fix_ver':'20.1.2' }
];

#20.1.12 is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12',
  '20.3.1'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv03478',
  'fix'      , 'See vendor advisory',
  'xss'      , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);
