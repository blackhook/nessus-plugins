#TRUSTED 2bd6f8f35274f7c8f2e561e50cd2aadfb087456c93a8b08cd39d40c23535f723a8794b130e7b92f7dbab84308eeafbd1e0ac35dd5b11b861bd64d67eaf7aa6b00d94a6a5b7a0582db52ddb524e4ee1b2b44a464bbdb716dcbe71fdc7b36862c76824afa366a97c993536fc8d21c6f144310d63045d880827994ef7d77ee10092b06619055db3921739b5f654554064d6f5dccd08a71b417a687ca55185eaa97acac96360ae7a074f0d26ff39ab35b9ecdee27c50f8a3f26e26db4652c97edf59c1715ece90310b5620a3ec5518d8d9a23d24fc4367ad85e30788d38a5bb840193dd19781e2a35161dfb1e209808e0b72265c2039ae98c4f0eb7d169ba5282968e9094352c6e2a21efb6f7f3b338a73c2648e7130346191662b26eabf74ab08caa5cd78111844b04a10e62a5fdb2bbc4cb8aedcf273441d02d497572b1e953d23684f608015208583a8f19216a1deba8b37394ba8d6318f42ca605b7f13859c88382ed6c2bb39d4eca56a8cc0e159837ca4c0dc3af7c56f53b8b028cd40bd760cce2612523e7cb7f40120f6cd467d1bbc5f427f42586e9d69fab3c63e4224da46b4762a8cf930d13c5394f6bf80fb4da7b9ceb8127c67245c8738c4d7e1026424f03646045e421a38f907dfe282817e955e62034878dea433ec44a657e16f02b934830cb32fca04ce2da896db7c19a1ecf4ec36b9914364710835ff25f4143720
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146266);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id(
    "CVE-2021-1319",
    "CVE-2021-1320",
    "CVE-2021-1321",
    "CVE-2021-1322",
    "CVE-2021-1323",
    "CVE-2021-1324",
    "CVE-2021-1325",
    "CVE-2021-1326",
    "CVE-2021-1327",
    "CVE-2021-1328",
    "CVE-2021-1329",
    "CVE-2021-1330",
    "CVE-2021-1331",
    "CVE-2021-1332",
    "CVE-2021-1333",
    "CVE-2021-1334",
    "CVE-2021-1335",
    "CVE-2021-1336",
    "CVE-2021-1337",
    "CVE-2021-1338",
    "CVE-2021-1339",
    "CVE-2021-1340",
    "CVE-2021-1341",
    "CVE-2021-1342",
    "CVE-2021-1343",
    "CVE-2021-1344",
    "CVE-2021-1345",
    "CVE-2021-1346",
    "CVE-2021-1347",
    "CVE-2021-1348"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97031");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97034");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97035");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97036");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97037");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97038");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97040");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97041");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97042");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97043");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97044");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97046");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97047");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97048");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97049");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97050");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97051");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97052");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97053");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97054");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97056");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97057");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97058");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97059");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97060");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97061");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97063");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-overflow-ghZP68yj");
  script_xref(name:"IAVA", value:"2021-A-0064");

  script_name(english:"Cisco Small Business RV Series Routers Management Interface Multiple Vulnerabilities (cisco-sa-rv-overflow-ghZP68yj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities in the web-based management interface of Cisco Small Business RV016, RV042, RV042G, RV082, RV320, and
RV325 Routers could allow an authenticated, remote attacker to execute arbitrary code or cause an affected device to
restart unexpectedly. These vulnerabilities are due to improper validation of user-supplied input in the web-based
management interface. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to an affected
device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying
operating system or cause the device to reload, resulting in a denial of service (DoS) condition. To exploit these
vulnerabilities, an attacker would need to have valid administrator credentials on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-ghZP68yj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496ff69a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97027");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97031");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97034");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97035");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97036");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97037");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97038");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97040");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97041");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97042");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97043");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97044");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97046");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97047");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97048");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97049");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97050");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97051");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97052");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97053");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97054");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97056");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97057");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97058");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97059");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97060");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97061");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97062");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97063");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv016_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv082_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv016");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv042");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv042g");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv082");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv325");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) =~ "^RV(016|042(G)?|082)")
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '4.2.3.15' }
  ];
  fix = 'See vendor advisory';
}
else if (toupper(product_info['model']) =~ "^RV32(0|5)")
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.5.1.12' }
  ];
  fix =  '1.5.1.13';
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'See vendor advisory',
  'disable_caveat', TRUE,
  'fix'      ,  fix
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
