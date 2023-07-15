#TRUSTED 65137c588de2eed43256d080fc18988e0b85d802d1597f9fecd47a0d5745887bd23cc0f79d3bd84068cc039b5336ad13d023ec9521a08bd9f4a0cb6069594abb625e7d2dd59bf73cf9bdffa9438741c11dd79bcd8dbd68fbfccdc702483d089e89ed33ed084476078944710adfb09a082f749c2566a18cd467c5c92a540dbac20d09b099fc2ecfa8c548bf399d9efa5e9656499bff708319088204f0ee8b772eeebf9c9e00c0a219b294584b066494dc94e49cc1f10e4f6486be42a579d23510c13d6702b5e6e1d199f98867a78e759b15d46866d7837d6325a3fc459e33d4e2cae6c59aabe4af79903c2911db110c6037f0048c2c5e4188cc7e059a54ffe545a5929820c567984179817171b9a00736ff3af003f513ce97580ae73753e1b4eeecde4b841f5ffc3c5d660223d8a70f581e3e636e97ba03558dd0314da8965dd59edc413ae7ae38932e59960c2cf83f655cdb77a20d9cd74509c31fe10c3935c9520984d19ad3cddfe3be0915a98d3670a10369af8632892ec0e916b392f0696ad9d5959c3c8f86d17698daa3c769288a59aded559d089a3d32f10cc029b492b52f66a6e13307fe465acc6b3af321e5e3a485dbaf811f4501ba044ff30079111c689a8f392b29a019f0994968090f0fc63d64ff584ca04849a94fc01216f98b8884190a9b098125b1ce82823a996d528ddbc7db04339bdb82acec6bfb6b87a0ee
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124333);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2019-1805");
  script_bugtraq_id(108003);
  script_xref(name:"CWE", value:"CWE-284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk79421");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-ssh");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Secure Shell Unauthorized Access Vulnerability");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - A vulnerability in certain access control mechanisms for
    the Secure Shell (SSH) server implementation for Cisco
    Wireless LAN Controller (WLC) Software could allow an
    unauthenticated, adjacent attacker to access a CLI
    instance on an affected device.The vulnerability is due
    to a lack of proper input- and validation-checking
    mechanisms for inbound SSH connections on an affected
    device. An attacker could exploit this vulnerability by
    attempting to establish an SSH connection to an affected
    controller. An exploit could allow the attacker to
    access an affected device's CLI to potentially cause
    further attacks. (CVE-2019-1805)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-ssh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f076a8ed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk79421");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvk79421");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1805");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.3.150.0' },
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_NOTE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvk79421'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
