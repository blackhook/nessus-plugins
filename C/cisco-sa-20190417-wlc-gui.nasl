#TRUSTED 0337109ff00c57bbd04ccd334aa0dee2a60154e40bb7c12e637a1c7b59a4042da18639be55e1f6b29835eb6788ee057c1a7292cd5f99fd8e43d0777bc837aa5dfb2e4dfabc6bb83e7347b16c02f124bb453751aebb16c12892dec6d1134d90ade6cabeaed82413819a6b569c58deead739ce26ec8078c37c848d325c48a860f7da72e5adfa9f52b209f9d77b8a72616d181962637737107d1ec2f02cde9d0f30cd832dff9b8fb76d3a112f49ee3786fbda26b61fa00d460a55cbf93b0c5179619278e894f04a9e0ae4a1fab474ead6f4a6d0322956c736db248a40607ab5faae98883426a4a188d704bf57cceab5ff9b38123517ec1a76b23d8be67c93843d36a3499670eedad4f331d841f4e73e42b37c79027a16f4de61da459cf79101ef3baf8634ec1959faed953dfdaf4046e189d24c31e323af58887064f8ad83799c0bed0de38a3a34858bac04ab4cc14a1db553dd09c528681d38425f89a97660ea8526ddd608f56ca5299cbb53a2a5bfe897f771078d790337aff52870c90dee28c5188adb23e147292cea4aa3d105aea8d05ec595168394d9a08742a31154dceaeeecf4fd34a3382be24e10821cba169c9933143af692898d4d7af7482905fa100f1a4c9b520f01df5bdb20c98d6e1976cc20d18ac55505489154f5e7cb821d075f7127747302f62cab3eb7cd9dd8365b4ee9e4862858a3cffc7c19533b862bc1cb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124331);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/20");

  script_cve_id("CVE-2018-0248");
  script_bugtraq_id(108009);
  script_xref(name:"CWE", value:"CWE-20");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb35683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd64417");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve58704");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve68131");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve82306");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve88013");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve90361");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve90365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91536");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve91601");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve92619");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve93039");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve93215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve93547");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94052");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94683");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94821");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94942");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95046");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95104");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95848");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95866");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95898");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve95987");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96615");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve96879");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve97734");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve97771");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve98357");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve98393");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve98434");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99020");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99072");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99212");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve99744");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf01690");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf02412");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf06525");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf08015");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf15789");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf16237");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf16322");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf16358");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf20684");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf27133");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf27342");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf42722");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47085");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47220");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47430");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf47934");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf54469");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf57639");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf58849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf59210");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf59796");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf59799");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190417-wlc-gui");
  script_xref(name:"IAVA", value:"2019-A-0132");

  script_name(english:"Cisco Wireless LAN Controller Software GUI Configuration Denial of Service Vulnerabilities");
  script_summary(english:"Checks the version of Cisco Wireless LAN Controller (WLC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Wireless LAN Controller
(WLC) is affected by following vulnerability

  - Multiple vulnerabilities in the administrative GUI
    configuration feature of Cisco Wireless LAN Controller
    (WLC) Software could allow an authenticated, remote
    attacker to cause the device to reload unexpectedly
    during device configuration when the administrator is
    using this GUI, causing a denial of service (DoS)
    condition on an affected device. The attacker would need
    to have valid administrator credentials on the
    device.These vulnerabilities are due to incomplete input
    validation for unexpected configuration options that the
    attacker could submit while accessing the GUI
    configuration menus. An attacker could exploit these
    vulnerabilities by authenticating to the device and
    submitting crafted user input when using the
    administrative GUI configuration feature. A successful
    exploit could allow the attacker to cause the device to
    reload, resulting in a DoS condition.These
    vulnerabilities have a Security Impact Rating (SIR) of
    High because they could be exploited when the software
    fix for the Cisco Wireless LAN Controller Cross-Site
    Request Forgery Vulnerability [https://tools.cisco.com/
    security/center/content/CiscoSecurityAdvisory/cisco-
    sa-20190417-wlc-csrf] is not in place. In that case, an
    unauthenticated attacker who first exploits the cross-
    site request forgery vulnerability could perform
    arbitrary commands with the privileges of the
    administrator user by exploiting the vulnerabilities
    described in this advisory. (CVE-2018-0248)

Please see the included Cisco BIDs and Cisco Security Advisory for
more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190417-wlc-gui
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?240d670d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf16322");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvf16322");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0248");
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
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.140.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.111.0' }
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 
  'CSCvb35683 and ' +
  'CSCvd64417 and ' +
  'CSCve58704 and ' +
  'CSCve68131 and ' +
  'CSCve82306 and ' +
  'CSCve88013 and ' +
  'CSCve90361 and ' +
  'CSCve90365 and ' +
  'CSCve91536 and ' +
  'CSCve91601 and ' +
  'CSCve92619 and ' +
  'CSCve93039 and ' +
  'CSCve93215 and ' +
  'CSCve93547 and ' +
  'CSCve94030 and ' +
  'CSCve94052 and ' +
  'CSCve94683 and ' +
  'CSCve94821 and ' +
  'CSCve94942 and ' +
  'CSCve95046 and ' +
  'CSCve95104 and ' +
  'CSCve95848 and ' +
  'CSCve95866 and ' +
  'CSCve95898 and ' +
  'CSCve95987 and ' +
  'CSCve96534 and ' +
  'CSCve96615 and ' +
  'CSCve96858 and ' +
  'CSCve96879 and ' +
  'CSCve97734 and ' +
  'CSCve97771 and ' +
  'CSCve98357 and ' +
  'CSCve98393 and ' +
  'CSCve98434 and ' +
  'CSCve99020 and ' +
  'CSCve99072 and ' +
  'CSCve99212 and ' +
  'CSCve99744 and ' +
  'CSCvf01690 and ' +
  'CSCvf02412 and ' +
  'CSCvf06525 and ' +
  'CSCvf08015 and ' +
  'CSCvf15789 and ' +
  'CSCvf16237 and ' +
  'CSCvf16322 and ' +
  'CSCvf16358 and ' +
  'CSCvf20684 and ' +
  'CSCvf27133 and ' +
  'CSCvf27342 and ' +
  'CSCvf42722 and ' +
  'CSCvf47085 and ' +
  'CSCvf47220 and ' +
  'CSCvf47430 and ' +
  'CSCvf47934 and ' +
  'CSCvf54469 and ' +
  'CSCvf57639 and ' +
  'CSCvf58849 and ' +
  'CSCvf59210 and ' +
  'CSCvf59796 and ' +
  'CSCvf59799'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
