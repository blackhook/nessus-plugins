#TRUSTED b1a293e18eafe7541347fff7d5160b9cd8632da10596b37b57a75f79bd7b060bfaa281ea3c01ba890da91c195139d268d02223c4d87b3c6ca1e46b232ccff33d1fc89d7194d83e7e89812d22f7ed3813216d97a6fd7876999d993a1c58695cfc69543a660b20e29e416a2720369a0425e5fe91def3744338d267a21dfde1c07d1456917ade635d551cc0e9ddf0fa27ee1fa805be472c4a562237bf0e237f2dac525103f25642fad95b3c24430afc063b8eb1ebe56504c9c713d93b67f19d726f28ae31bf86e7c0a4477609b68e64148cca06cd5495c0e81f169fe63e464829d74aaa72bf63373b410ca2b822549e16b9c45d39d88990868f3b08403f1f8af8a043cc93a86d45603af18aeaabb0949c21bef611679c40d1875614dfe24d849b36ae592a183d41ace4bca7702e24d8a050adac8836bb7bd148894be6135a400f1d0fd56ebe899e8bdcc3cf34deb7625ca797e9365d59c9c9a8bb37a7991ed8798307e7ab4bf82536bda60131b28511b59878f4fbf70e9698a46fc87e11de352357b76de65e3fbd26ffbf3cae67b62f48182b1a4a4f8e78a8c85c378f73e70d6bca9cc3d26ba65b593d6243034014583dd3f73b0242a456c6f5e7d57428698236da4e8c2b830d802bbe180bfc0327c65ddc3236185a6183fa2b709933e1fb8591434731836ecce96c01f82794924093222bba8801922990da1f112ba9ef4ae9d4b8
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149365);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-1514");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69989");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-privesc-QVszVUPy");

  script_name(english:"Cisco SD-WAN Software Privilege Escalation (cisco-sa-sdwan-privesc-QVszVUPy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a privilege escalation
vulnerability. A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to
inject arbitrary commands to be executed with Administrator privileges on the underlying operating system. This
vulnerability is due to insufficient input validation on certain CLI commands. An attacker could exploit this
vulnerability by authenticating to the device and submitting crafted input to the CLI. The attacker must be
authenticated as a low-privileged user to execute the affected commands. A successful exploit could allow the attacker
to execute commands with Administrator privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-QVszVUPy
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12b42902");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69989");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi69989");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1514");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
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

if (tolower(product_info['model']) !~ "vbond|vedge|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '18.3.0' },
  { 'min_ver' : '20.1', 'fix_ver' : '20.1.1' },
  { 'min_ver' : '20.3', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];


reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvi69989',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);

