#TRUSTED 95e1d7bb9274e597cbeb06576962d855e6d076c2374ec8fd52c4907bde894566984efa45e0835b96788ac15de16e563b4e38766a8c8194961570f36eb1d3dd6eaef83c264c03c2840a3f1338c5fc19437f1107492d1d6009e195a4fcb4f2de8d68d6659be805f408cd1293d4925d44cb165de1ef862effa9dd51be93dd63a4f508208d4977e67b31f9083e19518a3e410a8cbd9aab2b1f171105422d7b519018e68c5c044251598733b588ea74d45a960339f0d8c69900c8ca2740cb7e6f3845cadcb86f78068be977cce3a34f104c1db6775f7f5098f504e2e43cbc9fe70c5bce176042eae3da062b22b48e3b0048727285316f3f3bea44f5e3a9f2bb3981ad614c571772c5bd38969bb775583a57f5185cc679c18182b056f800b0fa01c37e5bbb9de8c58dfa67b8ad4149ea36d9a9d85f938203476c6e75dbb18dc0ed248a2a2fd223657055f08030fa918c44f64e9de02012191da6e21559f76aff417d6b4af506061411c29bc0d8af4a7d111ac752fc6a2ba25fdcbeba6311176ae41571c686b2658e4f81ce172c31549dc2a69554d7a98272f315597d3ff3932a5facd2bd83b27ec4e223519d31efdac958bb37e2c77dfcc88f0e419b538fe686a83da4bd9f3d68e3afe360e8b9d8ca1487248fc7cada249a353363df446d7bf56ad806131197e616d14661c5c32d91379facdeee6786902d60e2a655e7f67904635c3d
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160089);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2022-20695");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa43249");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wlc-auth-bypass-JRNhV4fF");
  script_xref(name:"IAVA", value:"2022-A-0174");

  script_name(english:"Cisco Wireless LAN Controller Authentication Bypass (cisco-sa-wlc-auth-bypass-JRNhV4fF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in the authentication functionality of Cisco Wireless LAN Controller (WLC)
due to the improper implementation of the password validation algorithm. An unauthenticated, remote attacker can exploit
this by logging in to an affected device with crafted credentials, to bypass authentication and execute arbitrary actions
with administrator privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-auth-bypass-JRNhV4fF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f3d9738");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa43249");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa43249");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(303);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_(wlc)");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port", "Settings/ParanoidReport");

  exit(0);
}

include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

vuln_ranges = [ { 'min_ver' : '8.10.151.0', 'fix_ver' : '8.10.171.0' } ];

reporting = make_array(
'port'     , product_info['port'],
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCwa43249',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);