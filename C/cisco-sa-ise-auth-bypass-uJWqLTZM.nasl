#TRUSTED 9b3c3e2ba33b29d132630d6729a03101266a635be0d449ff51b2d35883022408c3c904f6c805b61cd1a43805f53d58e812f0c9491fb99800ccbc0aab8401f29d989aadd1e571aae340d73769d8f1545602933c3145f501095850b37179676274b2b55b51c5909c6a5fcfe3d2db0f417f5df0073508fa9f443a359332e1c916732f864068e2e29682d4e1e4b1834ef9397a4634558f35c14a63c2e2c2ab843e5dcd6c51660d4f7aa5b22047363901d3c6cbeb04de96dceed069c4c53df01c920e634319709743a5a41d0892b37089d3a541846fdd5d2db1948f618b98c495e2b6413540feb0cb61953b23565c0ea45e5a643ad09594cc95033f61290ce51c9daa0c847e5932da8e578bea81d59e11829aa04280942f0a4023b3feee6302f685a26a41f928afbb3a098bbd594381eaa8e1a9e583584b4068f103539c09c9ac98c5f652935c7a258724b2e9588826293ffd2072b812002b9e8467657fe4d71680eaadf72fed8f083f44f9276a4b0ec8b9761ba0b7b26bbc9e6cc821ccd7f2af69d90d5fe90857f46fdacba5256938837be557ccd77e90d413bb5ef257340788699370d07c4cf7f3fd41fe8acac4a5bf3f03586a26572227064d9afe24d8496bc5b100bbcff89670d28cf3bd4aed239504640938a5f3af8f8ea5963dfa2561c5a2e9de7bac49048114dc0d2ef7f8e1703f7fb45e3f7f27e1818a38d420ffc42896f7
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141351);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3467");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt44829");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-auth-bypass-uJWqLTZM");
  script_xref(name:"IAVA", value:"2020-A-0450-S");

  script_name(english:"Cisco Identity Services Engine Authorization Bypass (cisco-sa-ise-auth-bypass-uJWqLTZM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in the web-based management component of Cisco Identity Services 
Engine due to insufficient validation of user-supplied URL input. An authenticated, remote attacker can exploit this, 
by submitting specially crafted URL to an affected host, to modify parts of the device configuration. Successful 
exploitation could allow unauthorized devices onto the network or prevent authorized devices from accessing the 
network. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-auth-bypass-uJWqLTZM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81f7d1fe");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt44829");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco Security Advisory cisco-sa-ise-auth-bypass-uJWqLTZM");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3467");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  {'min_ver':'2.3', 'fix_ver':'2.4.0.357'}, # 2.4P13 
  {'min_ver':'2.5', 'fix_ver':'2.6.0.156'}, # 2.6P7
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'} # 2.7P2
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.[34]\.0($|[^0-9])")
  required_patch = '13';
if (product_info['version'] =~ "^2\.[56]\.0($|[^0-9])")
  required_patch = '7';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '2';

if (empty_or_null(required_patch))
  audit(AUDIT_HOST_NOT, 'affected');

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvt44829',
  'fix'      , 'See advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
