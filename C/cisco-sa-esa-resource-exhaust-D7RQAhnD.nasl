#TRUSTED 340cfe5a21eef72f0396b8a8cfd9512e5d11450ae42ac1fc30071059492f7a0bdb39115aea5534805361e81d9eeb7108a9ebfc5c1be9de9c7755ca8b3c130d5cdb68e977f20096c023ff80d84c816fd4191bc9a8f1b9f5793a2ec919e2d12ed709ebc8b325d95445f7f5075f356428baabacceb8ca50064cbcd6bf37149a7cc913511f16985fa512b2a0f13e20f828031d638a6d5e873892cddc0aecae9cf04ab001a11e782053429cab88fc09b3972517dd584f26e3e98b79f00519847232217a2a8df59cf9b35d34dd3805fd6651ca5af0e89d4b773f0215d284bd780fc503624797c1e22b80588ea840c816579042fa5236fed5d358e295e1c30dd48e450f628884f2d4eef0fefeba1306cb74c67d64432a30e02aab7ecbd8dd958fbacc77089577f26d35ae9db6b7db5a939fdba702fe9fc118efc8f9e2705fe502c273ebec9fa63158704ce5a9f5863415586d6fa468fb08a4c49fb955c48cd30649fdaf7a75c887fe61c08e1a35b8b85eb725ee63a8e855ce2fca05c7297a3f6027d708831bca7980f685dd9e3814619cddf82d16fdce9aa1bcf70aa593d5ae7241e9d4630a1dcd94a259b542db04a516f264fd7cc95b9827eb0630bfd47fab3a804e0214048f963442df2131b6a7677c5962757aa4ad7ff10d9cd4ce86caf9294ae5d32d1a0351a5592d6e36bb0b28b15f15c7d068904de59855812f933d82fe28d7fa
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135012);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3181");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr96489");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-resource-exhaust-D7RQAhnD");
  script_xref(name:"IAVA", value:"2019-A-0368-S");

  script_name(english:"Cisco Email Security Appliance Uncontrolled Resource Exhaustion Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance (ESA) is affected by a vulnerability. Please see
the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-resource-exhaust-D7RQAhnD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02c3e52f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr96489");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr96489");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
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

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit("Host/local_checks_enabled");

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

vuln_ranges = [
  {'min_ver' : '1.0.0.0',  'fix_ver' : '13.0.0'}
];

reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvr96489',
'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);
