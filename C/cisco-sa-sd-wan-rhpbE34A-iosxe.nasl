#TRUSTED 233a753ca63c0e139f10b5c3d61c3b802296460ab2a5dbdfd2d9417a77dbe81eb914e4e347586f899bb7a8d55640596797ee964b9922fde3c34c238bb5497053990287415b852dbebb8ec6a2665a39d1fdce2c38f0618147c8afe7c884d00cd107ba9bd62c39bfc085e777bba1a9ebed0491106e8cf376d52e3e0ed97dfc518fc713dee93a92d6dda7ef99bb99e1b0b48dd5ac9f026448466d2142d7c917b2beae7506a3e9c24aae72a938353b20a2df875125498657c8a1e849d3baffe8736f1dc2c3c6005ee0d09dfbb6af652d3119ada823fcecdc5db3300a41dd3f9e1f384e590fda5e333ec3f9db7a4fd53add9dea49a8f844c754b362352a2cfe4699f9a0c1ab70930639454ac011caea32847ff90781eacda5a6a898855cdc28ae0c383c1e1ecac7cfd5be47329001fd54cfd52dad52e70352a7e859ac841de12d604d07516a8d5a00370ae1c9ed895b0be5d83511e9609ec77191d159e06c4f9ba7c7a68902d330257b077a4d2856e55a36e122918ba8400fa5fa312907b0a0cfe05c5c78d3f39ef2510ba2ffa450b644e425b509ab015e4534c0519fcf2d84dc76a8ff56f7fd65e3a45a6888d230a797cd54320b2dd2e883804207d93d27886b01ff4d665d129088077fe877cad5a6f1d7a452cb7124fe8ff02b913743e482efbc55e6f9c6a43033268a26a0f4012c5dadcb9dbc423dc386ee2b3205c72ad4da9680
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154348);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2021-1529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx50713");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-rhpbE34A");
  script_xref(name:"IAVA", value:"2021-A-0495");

  script_name(english:"Cisco IOS XE Software SD WAN Command Injection (cisco-sa-sd-wan-rhpbE34A)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A command injection vulnerability exists in the CLI of Cisco IOS XE SD-WAN Software due to insufficient input validation
by the system CLI. An authenticated, local attacker can exploit this, by submitting crafted input to the system CLI, to
execute arbitrary commands with root privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-rhpbE34A
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e79ed52");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx50713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx50713");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1529");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model", "Host/Cisco/SDWAN");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit('Host/Cisco/SDWAN');
var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Affects Cisco ISR1000, ISR4000, ASR1000, CSR1000V and Catalyst 8000 series
var model = toupper(product_info['model']);

if (('ISR' >!< model || model !~ "[14][0-9]{3}") &&
    ('ASR' >!< model || model !~ "1[0-9]{3}") &&
    ('CATALYST' >!< model || model !~ "8[0-9]{3}") &&
    ('CSR' >!< model || model !~ "1[0-9]{3}"))
    audit(AUDIT_DEVICE_NOT_VULN, model);

# Vulnerable model list

var version_list=make_list(
  '16.9.1',
  '16.9.2',
  '16.9.3',
  '16.9.4',
  '16.10.1',
  '16.10.2',
  '16.10.3',
  '16.10.3a',
  '16.10.3b',
  '16.10.4',
  '16.10.5',
  '16.10.6',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1d',
  '16.11.1f',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1b',
  '16.12.1b1',
  '16.12.1c',
  '16.12.1d',
  '16.12.1e',
  '16.12.2r',
  '16.12.3',
  '16.12.4',
  '16.12.4a',
  '16.12.5'
);

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvx50713',
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
