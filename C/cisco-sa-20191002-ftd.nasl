#TRUSTED 59d440eed5a60f0d7c114e13d687187b08960878791029e6cddad87315faa7c7b3ade968bf824119cde10efa596b1e6682ccd88cd83f614552050ea899249da1b67622c55d40a1f76cc7fea4c0e9d3227c2cdcaae242a798372909d4423c6b8b46cb2ae3585e087cf9aff8389835804312aed20c160195de9a8a5e39ec44ada203926f42b67965dd519e0285ec1f963cadd3769c7e27228feaba8f090e6ff77404a4099195c7ee4d26119edc944ea89ef163e86363e2bef90056c9193300e285a4b0eb471b95911394483fa991ac451b58c83a41f24034e59eff5ae0c32f0d9af17538344bd5e64ef69ef10fe2bc5f2136c94e7e7aa955d156816b1b8638991d11c0893c8418e9538c5209ceae840d9d86cc1433485571ffdbaa116592dfdbc44766465e51bc03a219bbd33dfc86c82fc8156db894b1a6cf0c05e6def36df4b3d9b730e99d0c577c88730cdf136fe4aa1cdef689786f6295a7d2b85b248e5d5c9f4cc91a53cf32cadc1329e954b4240388f3e52b34a82b5f14ea687567eae93f1733c1f38c87281161e68a930fd0767bcc1e88941ae50ef9391279650c13747950d2e5da8802eb5c7979d75c19a41790a7118d77a17834ad645bb0fe48c350350acfd8178c7071a2b2e720060b69ff88354052b3e531d40fc2358c18f2db37cb19e38f27da439df60f3fa34e4527642050c23a0588aa880d130a196718c4fe7d
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134449);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id("CVE-2019-12700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm92401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn83385");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-ftd-fpmc-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco FTD Software Pluggable Authentication Module DoS (cisco-sa-20191002-ftd-fpmc-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Threat Defense (FTD) Software is affected by a vulnerability
in the configuration of the Pluggable Authentication Module (PAM) due to improper resource management in the context of
user session management. An authenticated, remote attacker can exploit this, by connecting to an affected system and
performing many simultaneous successful Secure Shell (SSH) logins, in order to exhaust system resources and cause a
denial of service (DoS) condition. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191002-ftd-fpmc-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?481199e8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvm92401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn83385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvm92401, CSCvn83385");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_firepower_version.nasl", "cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');
product_info['model'] = product_info['Model'];

if (product_info['model'] =~ "^(10|21)[0-9]{2}")
  vuln_ranges = [
    {'min_ver' : '0.0',  'fix_ver' : '6.2.3.14'}
  ];
else
  vuln_ranges = [
    {'min_ver' : '0.0',  'fix_ver' : '6.2.2.5'},
    {'min_ver' : '6.2.3',  'fix_ver' : '6.2.3.7'}
  ];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvm92401, CSCvn83385'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
