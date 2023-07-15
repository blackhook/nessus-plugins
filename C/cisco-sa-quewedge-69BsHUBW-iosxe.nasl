#TRUSTED 87585bce509a35e048602f995edd9fd6b5ad5111a4692cb161816efd3065025be77a29c2780e4806cdd5cf629e041c4025fc448fc9767664c8293fb2abbeda7c38bd2776dcc0380297fafb74e034883f12b1e022799296287898804e4262751e93f265f7b27415a156fa925d572d212283d87073e3050aca259cc22b74e25a306a6995273616b7cd5705e81046d9eaf389b8e9d76c2977dc6751d9f6bbf5a22fcbb4394d19d4ece1294eb71a0c830e3bcc85d228b1e1ed611098505e207fea9ee16fe7bf0bc699c616cf9be86aacf8f5fa6466a58a1105a6a679c9f5e2db8209b76dd08fd5a897c12d6d0c4e3259da36459b17c59d9e6239f63f0797c7516624b2bd6ee42bb9b6ec719bbe3675148128a2ebe02bdf7be004156158b6da569b39f09ad475255e9f47dd228769fd41e3049f1072cab267dbbf8f7f4a6feec441cf5d3f92d98b3bd534d9e88a735110b7d095d692d7bf0da5dac5178747dd35307761bc5973dc2a124b018aca6a16a33dd5f216b2ca677020c1f94bd98f7e0244d8efb3db506e0b831cf7441a92cef73540f8ed6690f173dd69b1d47afdc35389350fa2d4f9afdf76dc354017f98487ecbe8f7c33f9a5b1a21f30eec6e460393baa4bcf36f020c0cdfce2871762656f76c9c6539e1f17b9a37dc89fa78cab9b943730c6dbad11a191e226c0aa97a75a36288bf22ecab084a760cea47315f43eaed9
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154197);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id("CVE-2021-1621");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw43399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-quewedge-69BsHUBW");
  script_xref(name:"IAVA", value:"2021-A-0441");

  script_name(english:"Cisco IOS XE Software Interface Queue Wedge DoS (cisco-sa-quewedge-69BsHUBW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability in the layer 2 punt code
that allows an unauthenticated, adjacent attacker to cause a queue wedge on an interface that receives specific Layer 2
frames, resulting in a denial of service (DoS) condition. This vulnerability is due to improper handling of certain
Layer 2 frames. An attacker could exploit this vulnerability by sending specific Layer 2 frames on the segment the
router is connected to. A successful exploit could allow the attacker to cause a queue wedge on the interface,
resulting in a DoS condition. Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-quewedge-69BsHUBW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f60b0fe");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74581");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw43399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvw43399");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Vulnerable model list
if ((model !~ "IS?R" || model !~ "1[0-9]+|4[0-9]+") &&
    ('ASR' >!< model || model !~ "1[0-9]+") &&
    ('CSR' >!< model || model !~ "1[0-9]+V") &&
    ("ISRV" >!< model)
    )
  audit(AUDIT_DEVICE_NOT_VULN, model);

var version_list=make_list(
  '16.2.1',
  '16.2.2',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.3.4',
  '16.3.5',
  '16.3.5b',
  '16.3.6',
  '16.3.7',
  '16.3.8',
  '16.3.9',
  '16.3.10',
  '16.3.11',
  '16.4.1',
  '16.4.2',
  '16.4.3',
  '16.5.1',
  '16.5.1a',
  '16.5.1b',
  '16.5.2',
  '16.5.3',
  '16.6.1',
  '16.6.2',
  '16.6.3',
  '16.6.4',
  '16.6.5',
  '16.6.4s',
  '16.6.4a',
  '16.6.5a',
  '16.6.6',
  '16.6.5b',
  '16.6.7',
  '16.6.7a',
  '16.6.8',
  '16.7.1',
  '16.7.1a',
  '16.7.1b',
  '16.7.2',
  '16.7.3',
  '16.7.4',
  '16.8.1',
  '16.8.1a',
  '16.8.1b',
  '16.8.1s',
  '16.8.1c',
  '16.8.2',
  '16.8.3',
  '16.9.1',
  '16.9.2',
  '16.9.1a',
  '16.9.1b',
  '16.9.1s',
  '16.9.1c',
  '16.9.1d',
  '16.9.3',
  '16.9.2a',
  '16.9.2s',
  '16.9.3h',
  '16.9.4',
  '16.9.3s',
  '16.9.3a',
  '16.9.4c',
  '16.9.5',
  '16.9.5f',
  '16.9.6',
  '16.10.1',
  '16.10.1a',
  '16.10.1b',
  '16.10.1s',
  '16.10.1e',
  '16.10.2',
  '16.10.3',
  '16.11.1',
  '16.11.1a',
  '16.11.1b',
  '16.11.2',
  '16.11.1s',
  '16.11.1c',
  '16.12.1',
  '16.12.1s',
  '16.12.1a',
  '16.12.1c',
  '16.12.2',
  '16.12.2a',
  '16.12.3',
  '16.12.2s',
  '16.12.1t',
  '16.12.2t',
  '16.12.4',
  '16.12.3s',
  '16.12.1z',
  '16.12.3a',
  '16.12.4a',
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.2',
  '17.1.1t',
  '17.1.3',
  '17.2.1',
  '17.2.1r',
  '17.2.1a',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.2',
  '17.3.1a',
  '17.3.2a'
);

var workarounds, workaround_params, disable_caveat, cmds;
# < 17.3.1 only vuln if it does not support autonomic networking - no 17.3 vuln version needs a workaround check
if (product_info['version'] !~ "17\.3([^0-9]|$)")
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = WORKAROUND_CONFIG['no_autonomic_networking'];
  disable_caveat = FALSE;
  cmds = make_list('show running-config');
}
else
  disable_caveat = TRUE;

var reporting = make_array(
  'port' , product_info['port'],
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvw43399',
  'version'  , product_info['version'],
  'disable_caveat', disable_caveat
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
