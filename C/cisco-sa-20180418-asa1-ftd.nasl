#TRUSTED 912ef80fda1f1e3321f131b41beb761e4f6fddcdebd4d24cfc4ebb684465880473f2571d21cbd2d52ce735ef3306dcca44cc2378fb8882252ad6d3a7e53585511df3c5ad9b2f8d4abc75b54835ccb648d107ab0e221219226bd623e5ea7d45346df66469c2d79966c8374c3a2ac018bd9007ef9bb69b72bc82c5520e2bb18c91213fc8006cc42e1c79bd75e3695bef2eee815f1eed5484338143cd073e36e8d1ef13a3fbc7731a31f5315b5a35a4388f7d90deccea4986abd1e5cac2a6b8e42ca9525b9f329ca448000acd3c620180de2dd48c8681b9b030b681e07722a714ecff42a7b70f2e083ff1c19b2f4fadb2e3d238fcc83f637f0757a89c16788dedfcf5a239bf40841b41113bfe18e259537ccb065cae98f66e8d0473891a67a339ce76c942d4b8f24119bdaedf0516911952a408b740f31d094ebca82a9580905db89759fecadcc501d2de8ae9c25376118284bd85d833bf04f0075a10d17dc8f0b7c679a0e924a4f4a9031b32aab035cff85cb73bd37488f05f508d0be172e956529accea041e36d335fe1d35b0bc3b57a42cdb12945f4c4a336a231f526af7971923fa6779214d53bef62bb799d7296d57bff218dfb28da30f6becf9b710917265845ebffa7086dbf36ec3644de9fc091ac5a21a777a95ef4fdd694b75356a06ca9cc9e260d12588a873d54fd0a319097d8c6e16ddb971ce2b877a3ed7b6f0aa2a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133044);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/13");

  script_cve_id(
    "CVE-2018-0227",
    "CVE-2018-0228",
    "CVE-2018-0229",
    "CVE-2018-0231",
    "CVE-2018-0240"
  );
  script_bugtraq_id(103934, 103939);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg40155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf63718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve18902");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve34335");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve38446");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg65072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh87448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve61540");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh23085");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh95456");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa3");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asaanyconnect");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180418-asa_inspect");

  script_name(english:"Cisco FTD Multiple Vulnerabilities (cisco-sa-20180418-asa1 / cisco-sa-20180418-asa2 / cisco-sa-20180418-asa3 / cisco-sa-20180418-asaanyconnect / cisco-sa-20180418-asa_inspect)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Firepower Threat Defense (FTD) software running on the remote device
is affected by multiple vulnerabilities. Please see the included Cisco BIDs and Cisco Security Advisories for more
information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3022fd51");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d86bee0f");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72e6e924");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asaanyconnect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496f5656");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180418-asa_inspect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcd24031");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg40155");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf63718");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve18902");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve34335");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve38446");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg65072");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh87448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve61540");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh23085");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh95456");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20180418-asa1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var model = product_info['model'];

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^65[0-9][0-9]($|[^0-9])' && # 6500
  model !~ '^76[0-9][0-9]($|[^0-9])' && # 7600
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower 9300 ASA
  model !~ '^21[0-9][0-9]($|[^0-9])' && # Firepower 2100 SSA
  model !~ '^411[0-9]($|[^0-9])'     && # Firepower 4110 SA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model != 'v' # FTD v
  )
  audit(AUDIT_HOST_NOT, 'an affected Cisco FTD product');

var vuln_ranges = [
  {'min_ver' : '6.0',  'fix_ver' : '6.1.0.6'},
  {'min_ver' : '6.2.0',  'fix_ver' : '6.2.0.5'},
  {'min_ver' : '6.2.1',  'fix_ver' : '6.2.2.2'},
  {'min_ver' : '6.2.3',  'fix_ver' : '6.2.3.1'}
];

var cbi = 'CSCvg40155, CSCvf63718, CSCve18902, CSCve34335, CSCve38446, CSCvg65072, CSCvh87448, CSCve61540, CSCvh23085, and CSCvh95456';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
