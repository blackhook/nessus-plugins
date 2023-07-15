#TRUSTED a84f4a1ffca4f857360c6ca27e5765280b52b586cebddf848a55cefed614eeea487b4562e237dfd5cd7195ff799a0757f1c2c16ad8ffb8ecce29f8f6edca24eeda2e339d7562876ef5a0250834c82094cb12200417cb082a9702ebdbbd1b4d3a81ade19d73800786a747db70591a2e607cce70ef25db4ee89d76fde5c8b3bf3d458954c831efa638740dffae310519540665478af6b7adb14c89ed4fd301f9fe61fdd6799ae53ee9e1d3e21acdd4d94be51be554d228a6bc1bb1ccaca7350fc24a6c942a1047c1506cd2963856d069a414c372c66153c39576c724b596ae1ba5590fd19dbd491ea796b043a2858e0e560aa305e922beaddf68e2d97ed46869e379e0761f3ec74dc7fd2d08b422a7c2d2efe1a51bee3580547e09ef791cdd2e89c2e3f7ba6d1ac692f9597f96ca686519319f7fdbf8df9c7bea0b8157444bb2b8bea08670fb15f4d4d4812bcdbeb9eaf3c18a17ed3d1365b53aac8d0f64904fcafaa83d2f3e6a906be55b9230515f1d1e26c4f734f0a633d9ec68aeb7e739f749a8af88120ee794b65bb1944fb53332e41a538aa3d5ebbe782d4621aed764c046ebf41b557b9de315c8778a5b728b1bd2bb4ecdebf549a87fa87a1376a62feac95fcb7b097c72b8e2b90fcdeb7211be77d6d53539c8f7e0bd5d652221e0e0e96a52243e878972b822424105a1342647cbfa1cccf8ffa0cac208d0763b859919e3
#TRUST-RSA-SHA256 6f95745b802996c30e2fccb78044a5be0f11b30b2450b63ae9e85eb1c79c4a7cb888cb461dfc1d095cd2924df94ef8b2f8054910996ad5a4fc07efdd2dd14d40c972f8802f1ddc52b5ec23d444f45eaf216b2fdc68dd351f70b9df5606623e30e185f538d8f575601fee7e8dd24ab6af7d5b36ba0d41038dbf791efc78f4b6bed5d6495b7b96a35005977c13362d77024561b18308db86d7d1263dfb468a4e7ca6170651978a7e77ae460d1dcc89f54041bf3446cb9768e600716d90bf6cb48706d65913744b887f7850d7d802c485bb23666565ff09d29de9cbdb076ca90c7982b45b5f947b3c189865c89dc103d419c78a72fa83f8d67d1396865c258893d0ac440503c60721ef7c1397374080c4abcda278b072419ae022dd14d05f15788d425ef96135f9bd5326df1c41635a245f4664ef8df879929076fc9b1809af7ff308f11132ea520e4fcdedb11c7f069f584fe99201896cd77af54c318fcc6778dca87770e4397d703830bab07347a957c077939ad5530c357bce42a000bc2675f93d6b3f4d9911d419c88adf218524f3748d1e3c2b162b08dc873bb5545894650d3abd5e0a7fdfcae254371fcfba9f52caa93e096c674904d64842df8f4438c01e33f86eb5ee84954c0865e476377dec87364fbd1829e24505abbca3343be7cb39a4a1b9ae4e3c8e50c4ebd220486c670ec4c8ad0da58f8ba28a883df17fd5b486
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165531);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-20830");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx43977");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-avc-NddSGB8");

  script_name(english:"Cisco Software-Defined Application Visibility and Control on Cisco vManage Authentication Bypass (cisco-sa-sdwan-avc-NddSGB8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in authentication mechanism of Cisco Software-Defined Application Visibility and Control
    (SD-AVC) on Cisco vManage could allow an unauthenticated, remote attacker to access the GUI of Cisco SD-
    AVC without authentication. This vulnerability exists because the GUI is accessible on self-managed cloud
    installations or local server installations of Cisco vManage. An attacker could exploit this vulnerability
    by accessing the exposed GUI of Cisco SD-AVC. A successful exploit could allow the attacker to view
    managed device names, SD-AVC logs, and SD-AVC DNS server IP addresses. (CVE-2022-20830)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-avc-NddSGB8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1a85803");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx43977");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx43977");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20830");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(306);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '20.3.4.120.3.5' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.6.1' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.7.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx43977',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
