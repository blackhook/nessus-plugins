#TRUSTED aee013a56cffc68dd8a83eb13ebcdb7113fe06255fe29f5793bb1b4aeb58c77c6eac23628c34aa09237031b5f50e22b0d5c6c271d4c6597e6e7a3f2564e89eb2adbe3ba8e962b2d8d90fb05ef20852ed80dd55fe11d985250b0313bead5c3b2bfcbb63b4b09225223f55f5dd0d2c8489b3e26747318b58704ffc38bb99024f28e568ffd8cf19989a92fbc093c5ef70e0014392ee27aa7650da252db91b4be072998b408834ab1fc9d18b16d0f27efad65c0c06d9075a070ee7b7bb57ab5b338ac5d1a82221ef48e64fd7ad2f999358ca807bd6895667599f1d72d697de06d8c529731cb7d2706e3099dcefb036556361ef7e372b655ac0d3e001a15ea2e68c4d14508350ca5cc5cead90233978ab3eacbca8ae1966ee1467e3e4934e69abf8404ff971ee6d7598a4587f90bad40ca10a92f18bb51d07dedc51d1ec4d91e31c7d530cf3db6a1997a7fb7491c3e2226f359ed6706781c6bcd289e98c4b9f10ca480ad29768fa84e61a6852ae026991a00ec31523306921647cd470be22add5e6030e419de57ba964f4ab28a18b9b9553d4c5132f8f11b55b06eee3d0b50a7fc684a21a5b0e5339f6e443d7f78374b06a265c61c9f564ace6a191b30b886696ae3689e480ad2a33f3bc93fc3bc4921fc47691a2ac9cca7b5e61b28bb799dfc74a33ab234aa065d8e5c9113020c526966c7b5aab6105ab65cff8f497f104b4bc17cc
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151154);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2020-3595");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv42551");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vepegr-4xynYLUj");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-vepegr-4xynYLUj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Software is affected by a privilege escalation vulnerability due
to incorrect permissions being set when the affected command is executed. An authenticated, local  attacker can exploit
this in order to gain root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vepegr-4xynYLUj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fdc038a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv42551");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv42551");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3595");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
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

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.1.2' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.2' }
];

var version_list = make_list(
  '20.1.12.0'
);
 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv42551',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  vuln_versions:version_list,
  reporting:reporting
);
