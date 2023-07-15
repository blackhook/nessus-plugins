#TRUSTED 6f736870973ed8c050a83859539402844986be45d939310d43b09d1da4446014968fc3a2bad0ca8f049f09621b812d5b09262bfae1763be2d411f242dbd541a29e7929d5b932907d300693b0a46f8b13342e44ccd8e42b70aae7b35bcd38425a58dda139aab86cdf420a2ada4b8a98d21fbb649335514374746e2f032bf1647de9cd16e4f10caa9e19becd6a3dffb52792cd753367860b1c690197db0aabc16177048bf223dde292973a308a4dfca04a0b501c4bd1895c568c0a3a20804f080a3bc78c18a0a41150f582b33c287fb52d65877eeae98fe43bbcf2926fa0c05ec81cacf675b707ce3e14e4c968eacf8085127e8e25fa363861a0f02dca0f9ec44f26d5c03fbf82a754607abc790c42cc60f0ce10cd70212e0cb6df47cac3af9b767f1aff531f42cfa08b0883a084d01514b6fe8b461bea30c0a41c84d248b463d3037a1dd02b3bb0903fb6c47e769f92fe9645cecc626e6b763cb025955d3a3d8b430dea053af48382ec6fadf781427f1135ec1a2eebe39b443eae777df0ff563f100261d647d24293b3190159d812830d12ad950f1bc116ae691a0d5600566cea6688681ee6aa82e9baf53cad1c8e799b25710b9f28cd0b8c99b143e2855aac493683109c7c4d1c39030b2e16f6af6e46df94f37aaf41d395632b9fa15f17ff614f918bf4f1f3e1819d38b8df938a5f82df445759466aec02e984e4608b1960ee
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134232);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/29");

  script_cve_id("CVE-2020-3166");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo42637");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20200226-fxos-cli-file");
  script_xref(name:"IAVA", value:"2020-A-0085");

  script_name(english:"Cisco FXOS Software CLI Arbitrary File Read and Write Vulnerability (cisco-sa-20200226-fxos-cli-file)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Extensible Operating System (FXOS) is affected by an arbitrary
file read and write vulnerability in the CLI due to insufficient input validation. An authenticated, local attacker can
exploit this, via crafted arguments on a specific CLI command, to read and write arbitrary files on the remote host.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20200226-fxos-cli-file
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0375756");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo42637");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvo42637");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3166");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_extensible_operating_system_(fxos)");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('vcf.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

app_info = vcf::get_app_info(app:'FXOS');
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'FXOS');

# Firepower 4100, 9300
if(isnull(product_info['model']) || product_info['model'] !~ "^(41|93)[0-9]{2}$")
  audit(AUDIT_HOST_NOT, 'affected');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.97'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.155'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.238'},
  {'min_ver' : '2.6',  'fix_ver': '2.6.1.157'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_WARNING,
'version'  , product_info['version'],
'bug_id'   , 'CSCvo42637',
'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
