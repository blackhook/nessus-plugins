#TRUSTED 8d9daaa017883d18b854891cd959189c781d0e8c1d40779e1e77dac23df277382f131c536eb416b010b8957e2e7dc2ac06a074fa19db979cf9c45dd331519ad55081be1433e8476a67f0290dbe2029484c41c0893d9cf6d945cf2947812f14c7227d106cabba8351ab3450ef655956308b2a533ff0c00465ecc2e6c34a9db470bb364e4955595e8610d79c0e8c52c047727478e792d35da4a7a430d0d182d8e7ec2803b6ec9c9ec0c6cc04a5c670e8bf10987d9bc57b053ac73a19a2bd2c29c23632064e3041e68d17a904fc9f2a45c1dc3e0492b5f846547c24f10836708bb6a3f863abd343b8d76626a25eaacebb7cdd7221e2784f748129c0679f039e430071322b05aa89920c9f803d7c92c9a4902fa0ebbc7a735214efb79a396371890ccd1c8c545d1d0d21fb8284fe22b06948f597aa23335b6bf7a1010ca0b7e016292772fc2fef7690ed4a7c205beaaaaed64ca9759393ae3d5348e1e62d809c21ea1e77e8d7f34ca847bbb0e784b6a6075a51b5fe5933c3fc9230c145c3d87af27efe740f1759406e1663eb5152b5834c98bdbdd08e7681da88812d0c36c58c065ab46fb7e0be7d28c3e47d81bb27b165cd3e57d25d20966f0be9df45e037dd631e14def7230440bdc578050b8fa79eef30059a4a435ded4e2637d8b5c2ff3e7573a3d6a5cdf153a68033f2e6e538d8739200858169cfd2bd820ef2f0b2a72c1b40
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139068);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2019-15971");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh88851");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-esa-mp3-bypass");
  script_xref(name:"IAVA", value:"2019-A-0368-S");

  script_name(english:"Cisco Email Security Appliance MP3 Content Filter Bypass (cisco-sa-20191120-esa-mp3-bypass)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a vulnerability in the MP3
detection engine of Cisco AsyncOS Software due to improper validation of certain MP3 file types. An unauthenticated,
remote attacker can exploit this, by sending a crafted MP3 file through the targeted device, in order to bypass
configured content filters on the device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-esa-mp3-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5841591");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh88851");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh88851");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15971");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '13.0' }
];


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvh88851'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
