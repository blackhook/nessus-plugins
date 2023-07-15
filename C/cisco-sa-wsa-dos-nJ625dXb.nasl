#TRUSTED 95216b1435084f45d09f810ace240c52a8b8db7fa36dee03fab121a3c4b14eeda7d4f79498535fda7579a064eb50ebf8e4da03f45a33cd38b3abd89d66d915694060f8b65907ec7ad6c4181b28e8b32e5604ddf7bb8aaaaae5371ed415a4c5c998e986e66c28ca30021f1f7fe98b8a1c69d81a5e908cdc77dcac3ae2e76bd556a11ad87a8c4b754baf69f5ec899e792e3441bbdc3f8af659e53419064cc65335fa2c92b9aaca00b66728f63c080ab28d4dbeb9230f51716cead3667aa5f2bb50f58290bb3bac8321d1bc150634d23b20b816d5c706beaa91004dcc368a4cd94f5a5e9ab954c0339648ff037457b1c2fa2a80e2d7290f83cd0b07c245766a2edabdb5a92f3123fb2684b1a225a003e0fb2a285cc9019517fbbfd30eedad78b40c498573eadb6f9b382f531d4bf62a2c6466b9f32ac2d853541facfb19b5a721903f02aae5dcf37261414df5ef8a21cc808b941b1b24a294d8812d7ee075d6eb896654e906ca184d0c3e686514b55e12f9d242f49d5135a9979ce700a9f32c7dc1c3a62359b2b3b0edbcacd7a00d1d83a2941390dbcbda69173eb9a5f9a898f071d3251fa01873a700c40ce837210835cf823daeb42ae625d4b08f63b6560d4d32b940e3863d9b7bc273e91a0bc2560351143a92b53ee1928480af09a2752936acf93903ee197579404e1ca1ea62b67cee5af5d9ee52e0ebc1ac8050aee05779bc
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134446);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/14");

  script_cve_id("CVE-2020-3164");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq96943");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs33296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs33306");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cont-sec-gui-dos-nJ625dXb");
  script_xref(name:"IAVA", value:"2020-A-0100");

  script_name(english:"Cisco Web Security Appliance (WSA) GUI Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security Appliance is affected by a Denial of Service
vulnerability. The vulnerability is due to improper validation of specific HTTP request headers. An attacker
could exploit this vulnerability by sending a malformed HTTP request to an affected device. A successful exploit
could allow the attacker to trigger a prolonged status of high CPU utilization relative to the GUI process(es).

Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cont-sec-gui-dos-nJ625dXb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bded73ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq96943");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs33296");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvs33306");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory
cisco-sa-cont-sec-gui-dos-nJ625dXb.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3164");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

# Cisco WSA Release 12.0.1-268 and earlier
vuln_ranges = [{ 'min_ver' : '0.0' ,'fix_ver' : '12.0.1.269' }];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'fix'      , '12.0.1-269',
  'bug_id'   , 'CSCvs33306',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);