#TRUSTED 99a772d478b76b9fb12311b20adf07590ecbb88886db938a9a4086e348e436d85a18552baf277bc6c5fffd4798f386987c86dc2403a012c2eefd7fd6d2118517e1233f3afecdf8c28bda808f22de8e804bc348b9d399d15523fcf43554b9ace4cc6acf0cdf8f304ad9d11d54ea2885d4e6209dd5eb97466d146102ebf3aa6c96113a25934c6d068b2d7690a5c761f893aa636a0799f023f3839c81330ed8faf180c91066dbe8aca0931998724b9b99da750a1475c1d518b15a3142d0d3a2cb1a81d79fa1da8d92f86a64ae4052d36ef1db5f9fce6607b7341f2f6f4d39e32378232939b172dac6207a82e62f798dc829f1cdf2309309ea816ed722473451ace43ddbcfb01bb97ad0dedbf96dacc2eec063024216f05fcbcf44cfcb83596cf76ddf79152a55b5555394ed6b8f2f5dc2d365fe4be02caf4ce91979222c13f737ffbc4772630bbc6957aea061ee01c2e54e8eac955a017a6ff925bf8543be09865c9e819ed4c8a5416bc5bd7cea35d786df984291dca9ee6e7d74a9d2d8558ef56e53a72ba7b3980832e04a7851d4c1f4d05a9cde18c1d0cc0b72103a16e46ba9c17036493cf960fc6c968af24899f3f276f77c105633bf44f7db87f86b966f5b432fe0b6a4b926ba805025f3856e87e061bf9df76cd702beb8b5127b7f054efdad7e9afa72b284df263347de0a968b702ee0390ce6e9e242286dcd9c885eac49bd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129537);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/07");

  script_cve_id("CVE-2019-12672");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg18064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190925-iosxe-codeexec");
  script_xref(name:"IAVA", value:"2019-A-0352-S");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution Vulnerability");
  script_summary(english:"Checks the version of Cisco IOS XE Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a vulnerability.
Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190925-iosxe-codeexec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0cbac58");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg18064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvg18064");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12672");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(59);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0); 
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

model = toupper(product_info['model']);

version_list=make_list(
  '3.18.7SP',
  '3.18.6SP',
  '3.18.5SP',
  '3.18.4SP',
  '3.18.4S',
  '3.18.3bSP',
  '3.18.3aSP',
  '3.18.3SP',
  '3.18.3S',
  '3.18.2aSP',
  '3.18.2SP',
  '3.18.2S',
  '3.18.1iSP',
  '3.18.1hSP',
  '3.18.1gSP',
  '3.18.1cSP',
  '3.18.1bSP',
  '3.18.1aSP',
  '3.18.1SP',
  '3.18.1S',
  '3.18.0aS',
  '3.18.0SP',
  '3.18.0S',
  '3.17.4S',
  '3.17.3S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.1S',
  '3.17.0S',
  '3.16.9S',
  '3.16.8S',
  '3.16.7bS',
  '3.16.7aS',
  '3.16.7S',
  '3.16.6bS',
  '3.16.6S',
  '3.16.5bS',
  '3.16.5aS',
  '3.16.5S',
  '3.16.4gS',
  '3.16.4eS',
  '3.16.4dS',
  '3.16.4cS',
  '3.16.4bS',
  '3.16.4aS',
  '3.16.4S',
  '3.16.3aS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.2aS',
  '3.16.2S',
  '3.16.1aS',
  '3.16.1S',
  '3.16.10S',
  '3.16.0cS',
  '3.16.0bS',
  '3.16.0aS',
  '3.16.0S',
  '3.15.4S',
  '3.15.3S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.1S',
  '3.15.0S',
  '3.14.4S',
  '3.14.3S',
  '3.14.2S',
  '3.14.1S',
  '3.14.0S',
  '3.13.9S',
  '3.13.8S',
  '3.13.7aS',
  '3.13.7S',
  '3.13.6bS',
  '3.13.6aS',
  '3.13.6S',
  '3.13.5aS',
  '3.13.5S',
  '3.13.4S',
  '3.13.3S',
  '3.13.2aS',
  '3.13.2S',
  '3.13.1S',
  '3.13.10S',
  '3.13.0aS',
  '3.13.0S',
  '3.12.4S',
  '3.12.3S',
  '3.12.2S',
  '3.12.1S',
  '3.12.0aS',
  '3.12.0S',
  '3.11.4S',
  '3.11.3S',
  '3.11.2S',
  '3.11.1S',
  '3.11.0S',
  '16.9.3s',
  '16.9.3h',
  '16.9.3a',
  '16.9.3',
  '16.9.2s',
  '16.9.2a',
  '16.9.2',
  '16.9.1s',
  '16.9.1d',
  '16.9.1c',
  '16.9.1b',
  '16.9.1a',
  '16.9.1',
  '16.8.3',
  '16.8.2',
  '16.8.1s',
  '16.8.1e',
  '16.8.1d',
  '16.8.1c',
  '16.8.1b',
  '16.8.1a',
  '16.8.1',
  '16.7.3',
  '16.7.2',
  '16.7.1b',
  '16.7.1a',
  '16.7.1',
  '16.6.7',
  '16.6.6',
  '16.6.5b',
  '16.6.5a',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.4',
  '16.6.3',
  '16.6.2',
  '16.6.1',
  '16.5.3',
  '16.5.2',
  '16.5.1b',
  '16.5.1a',
  '16.5.1',
  '16.4.3',
  '16.4.2',
  '16.4.1',
  '16.3.9',
  '16.3.8',
  '16.3.7',
  '16.3.6',
  '16.3.5b',
  '16.3.5',
  '16.3.4',
  '16.3.3',
  '16.3.2',
  '16.3.1a',
  '16.3.1',
  '16.2.2',
  '16.2.1',
  '16.1.3',
  '16.1.2',
  '16.1.1'
);

if ('ASR1000' >< model)
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['rp_check'];
}
else
{
  workarounds = make_list();
  workaround_params = make_list();
}
  

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvg18064'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting, 
  vuln_versions:version_list
);
