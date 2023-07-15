#TRUSTED 473d58a29f276b1744e0b149e028672e4e07ff4cb2ad1315e6b956f87ad9400b89afd8542ccaa52ed78a4d8f12b767ac21ec773880e19d23c5a98f987033d583453a974ebf168ba8732b1ee6cd0ee1cfb223705270d19b91e4d82102b40c63fe0e4ff70aadb23df9b1ff64abb6e909ae72025b52a8c8da40f0fce3238ad15b750c7203c5ede113b95c452cf404115d3120196274828410ee1ed4f58092b611fd189b63efb313ddfa08dcf3b5fa8cff518eab24b13d1e398645c650cd2dd42bd70b953c0f022dc41a31b55bb1e437e07ae8d16906605d82dae0619826c110f18b74ffa0ba4d23c83a8142f13abd2442bd78b61bb36589fb34177c8e8cebcb2b2b5ea9feb7942d8baabfc887bedb73d43eaba82e77aab56d212fbf1a416760449ce0b67c802e6f0e47fff4ba697fc2fd19eea4e33bc14753140ff2e0a0b806444aa3542e3e657a369d954766aae239bb7e867cb4772f7fc35d76b02384f834fa76cde9ae13b48e71643cf0cf5710a1aa7c95a5feedba706c52d620d94639feb5b1cf5b4b687071ebf8bd8d510daebf9aad3a469b898bfe106127251f88edf3451288b9aecfae56e404025f90de0b293e75ac89d5271096fb6a05db5fb432dd74de349393f967204e5c4656ee7b1d12794e11d34d76fecb6802c08875bcdab7d62cae2caa11c8f6e121b9969a9a64932aae7e93bd4f238802ab4be68ff3b616cc19
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(142660);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/24");

  script_cve_id("CVE-2020-3592");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42602");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanuafw-ZHkdGGEy");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Authorization Bypass (cisco-sa-vmanuafw-ZHkdGGEy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by an authentication bypass vulnerability in 
its web-based management interface due to insufficient authorization checks. An authenticated, remote attacker can 
exploit this, by sending specially crafted HTTP requests, to bypass authentication and modify the configuration of the
system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanuafw-ZHkdGGEy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f98255ce");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42602");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42602");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3592");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

# Both versions here stated as vulnerable.
# Note: 20.1.12 was released _before_ 20.1.2
vuln_versions = make_list('20.1.12', '20.3.1');

vuln_ranges = [{'min_ver':'0.0', 'fix_ver':'20.1.2'}];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv42602',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  vuln_versions:vuln_versions
);
