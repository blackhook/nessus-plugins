#TRUSTED 2144fa102710ec56538f3905eff64caf60689889c06aa96ea9f77056ee4ee20df2dece13497ba9a5aee47cc3089492c010d40a707f2bff4dbe2404beb639ce8463e556afbe4a76c980c8776f63f9e4984b4273f61fac007f583793274a22150b63c5c552217b51524fd42560c2a5b9052fac728d86bd01a5e576ca164b9f88d302ccfe2a97fbadfc36e957d7acedae533a60e94faab7808cbe1a2a7286fa6da3d7a8d506fc7209166b9d95642276fa0f16685d69adc72e7482a2c251b5ad1987e04925f7e1c2fbf1195466311a86247b1d4f3a37ad37cb7b620629f92c8a8d9a58ea69acac431b408db5a0f5103db6cfa8467fa3f02c3e83ca299a577c1d1692c42338b35656e3ec270da0722a7a38ecccd149b482f7faf29318de5fdcac02f0969a981063d22d5e20820a111adaf3b1257a9a6a9a6944261111176750b1d187d6f5d6cb94767e75f20474f8e886a48b0c2929722ad6f7fcada744ab0608a7566e5810135fd05b51ea90022c65c16911103924d586317d22e5c56f1ce40b02d2a997afea5f0e2f9c1450fb946de92a148ad09b12abb11b322176ee05f76739f39c56e693293ace8a927668bc644ea7628d73caadab1635772849fbf60d634f2a35ce962c9a04643371e0c2707514c2878795c778004dd3393be2e1a9f095ac9e0cbdecb14694af402b2d5097f1d9550c1b1de7c0b3c3ccffad027d13eccce495
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138092);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-3221");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo68398");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-fnfv9-dos-HND6Fc9u");
  script_xref(name:"IAVA", value:"2020-A-0239-S");

  script_name(english:"Cisco IOS XE Software Flexible NetFlow Version 9 DoS (cisco-sa-iosxe-fnfv9-dos-HND6Fc9u)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-iosxe-fnfv9-dos-HND6Fc9u)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a DoS vulnerability. Please see the
included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-fnfv9-dos-HND6Fc9u
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79ae6bc9");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-73388");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo68398");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo68398");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/device_model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = product_info['model'];
device_model = get_kb_item_or_exit('Host/Cisco/device_model');

if (device_model !~ 'cat' || (model !~ '9[35][0-9][0-9]([^0-9]|$)'))
  audit(AUDIT_HOST_NOT, 'affected');

vuln_versions = make_list(
  '16.10.1a',
  '16.10.1b',
  '16.10.1e',
  '16.10.1s',
  '16.10.2',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.1c',
  '16.11.1s',
  '16.12.1',
  '16.12.1a',
  '16.12.1c',
  '16.12.1s',
  '16.12.1t'
);

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['section_flow_wireless_profile'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvo68398',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
