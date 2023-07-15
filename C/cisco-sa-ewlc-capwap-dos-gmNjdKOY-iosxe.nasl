#TRUSTED 1797642330269481040e84c2d5a1ffcd5f76e04390c6f3df499552e8f443a3e31f5bd4a49c2bd79f696277a286f8140e24ea5f3c300ba454423460d8f7977574be8d79b337bf8cd3c7f50fa4797c4991775038be758847f754911ff874a869433e018800e70397314a5eb656568b4fddc8e6585b388fcbb905448742331e80f1cf1d54bf18d132ba26033939ac452e633ca32e83a713810d12be2b0e060fcaaab69d791f07168ce5297124710542313843bda76d28034ace742161538f20b83a751eb056486bdb7b3921130045ff342a0824f52de992013e29db71e0c96964bb78d71b8c4a9f11705616486b3efa1c1842255028eadcb6373e71634d70802b97e0245378f7539e4cdfc7ec5f19af8426ca3fa956c67369407f9770e4f9e6bd6ef5ffbed780485d1caf3120f1618889330ab5d66005962c74c52429971833b6cf895f2efba51d552d2427d75084bd4369c2ee52aa3171802832756117160dc706ab1b753938d7e9869bba348042bb7ddddc744388799906c44081ea400414567c035b420d79150489bd09a55ce10ed94c8d61b016e128111ba292bd66e467f1497964157f908ff2fb052410eec3ac5bb5a5dfd870360c19abccc567a13f607d25dba7d3d53c86bac951a14cbe259ba13e501328e1df54a2d1ede0e007f1570cda52464c3615cb8df3303430a35630f1d56995e0b9690f18862b440bde0b6fd42a
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153563);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-1565", "CVE-2021-34768", "CVE-2021-34769");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu73277");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv76805");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03037");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53824");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ewlc-capwap-dos-gmNjdKOY");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Denial of Service (cisco-sa-ewlc-capwap-dos-gmNjdKOY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by multiple vulnerabilities.
  - Multiple vulnerabilities in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol
    processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an
    unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. These
    vulnerabilities are due to insufficient validation of CAPWAP packets. An attacker could exploit the
    vulnerabilities by sending a malformed CAPWAP packet to an affected device. A successful exploit could
    allow the attacker to cause the affected device to crash and reload, resulting in a DoS condition.
    (CVE-2021-1565, CVE-2021-34768, CVE-2021-34769)
Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-dos-gmNjdKOY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ab5cb4c");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu73277");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv76805");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03037");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53824");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu73277, CSCvv76805, CSCvw03037, CSCvw53824");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34769");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(415, 476, 690);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');
var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ '9300|9400|9500|9800|9800-CL')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '3.15.1xbS',
  '3.15.2xbS',
  '16.6.4s',
  '16.10.1',
  '16.10.1e',
  '16.10.1s',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.2',
  '16.12.1',
  '16.12.1s',
  '16.12.1t',
  '16.12.2s',
  '16.12.2t',
  '16.12.3',
  '16.12.3s',
  '16.12.4',
  '16.12.4a',
  '17.1.1',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.3.1',
  '17.3.2',
  '17.3.2a',
  '17.4.1'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvu73277, CSCvv76805, CSCvw03037, CSCvw53824',
  'version'  , product_info['version'],
  'cmds', make_list('show ap config general')
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['check_ap_capwap_config'];

cisco::check_and_report(
  product_info      : product_info,
  workarounds       : workarounds,
  workaround_params : workaround_params,
  reporting         : reporting,
  vuln_versions     : version_list
);