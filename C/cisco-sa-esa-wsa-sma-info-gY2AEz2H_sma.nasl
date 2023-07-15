#TRUSTED 1a075eba4be4c2947145b0f74177f83c216fcb2df8a0ab3a0028da60556ef48691a25a0ce4abd4899d231fdd6778fe66a2025095862709656ce26ffaf27ae23e247bdbe062d38e26a7b64873790efbe76f3378d6194a4976230722f03196244461ff3176651314f301388253016b204db538f991c7eb5a325233b073561b481a5654197c28f4a1d452e3442514547a988a7a131ba34fa2dd033992db90c06d658149b4663a78f097076090a6dc1e08230e9c2f3f7317a8919ca5c0ea30b1e0f0f2516d4daf383e446d4af82485b996f6085f82774bfe612ea03855f64a27bc71ca1f7ad5bfedbc13fadf9fab755f26f3a1dac2affcae046c1ece47df09b05600950c0d131e5e03f2bdb8066fa48ea655c59af89cb4b9779f7b2dbe2bd36b73b4e94583eb453434a13558bb453124c381aaaf5276975aba128e8714345e208b33b4a8837ddaccad3b26300dce4aed20a0766a34974e4f4d60223372888dd6a4f3f2d4091b218c368c10420648320dbbf20dff99a5c89bce16b91d52f2794b5d02bfd6c7754db59ce6f7755a9cab3d60230165d62b22b6895cb4c6f5fb1c19967a24d0eb3927ebe01941708f4f14c0f40e16a88aad892414820d3ae2494261d368dec898d10b5a9597c86222c8456be81642bb2479b1c006580d50f7e41f4cf642136d347331fbcc358964bf9439348225ce0a6aba04ed4b917d097700f03c32f0
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149842);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id("CVE-2021-1516");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98333");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98422");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03505");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw04276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw35465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-gY2AEz2H");
  script_xref(name:"IAVA", value:"2021-A-0244");

  script_name(english:"Cisco Content Security Management Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-gY2AEz2H)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Content Security Management 
Appliance (SMA) could allow an authenticated, remote attacker to access sensitive information on an affected device. 
The vulnerability exists because confidential information is included in HTTP requests that are exchanged between the 
user and the device. An attacker could exploit this vulnerability by looking at the raw HTTP requests that are sent to 
the interface. A successful exploit could allow the attacker to obtain some of the passwords that are configured 
throughout the interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-gY2AEz2H
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?156a645c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98333");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98379");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98422");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03505");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw04276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw35465");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401,
CSCvv98422, CSCvv98448, CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(540);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401, CSCvv98422, CSCvv98448,
CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
