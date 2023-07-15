#TRUSTED 2dccc5f2765f4041197d265a12b4589fd14091c9526c3f669cc66ec6c1184db9a93ed0eb0d003112f1d21d5e364d61bd9b1250b2f64b1cffddb2e70762d0773de120c61ff966fb0136ab2de0aff39de4660b59fbe82d2b474cf981662cfc1154669e47b3b3e91c57adc970c27f0ab4ab906dcd1f91fcadca565ff1025f23bc8d785f67f26967633b241fb7e1d30ae9ff485b4f9d5493dbea65abff4c2bb49214f0f6a1899301c6ead2eebc81dfb2f2e8d3581076bb90472f0c2f6a0c4ac279dbadebeb625b6014e6e02416c0a06449c3dcb5b20854b98f6afbb8c881b8d58bf4e1aa04041739e6014983e620f82a878c87d66b9c6fd22714228340345647401f88b5f5f6f51387d1b897d73244d82960047a8c842cb3a48dc5230d3c525134f5a95c8bdd87dd007490f39b40d8fb1f15ad957307005824ac88da6fc407f6c2a57a09eecf050e4e67216ea81beb53ecd1baf979616a53c8c274552f978b57f7d246ec7a1ee1cc14fabafa6e4c1e4a27b802d2796c2ea927e76d0508aae7d13472327b15fdbfe627c96635bebec83ef07bdb0e3b0473bafc0788ca27dc2fb573efa2382ca93715854cc7be3439ca0b120b8c572ca49b2204ad35640ebbfcc49a909c4bb8bc281d9a46a7fae6ea49c144c7b0b190e924b92c6b0b5ebd7b81ed110e19dae3540bc535d75a608c44136c00a699863a3c6fd3cfbcb385c10150e43e05
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134450);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/14");

  script_cve_id("CVE-2019-12700");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm92401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn83385");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191002-ftd-fpmc-dos");
  script_xref(name:"IAVA", value:"2019-A-0370");

  script_name(english:"Cisco FXOS Software Pluggable Authentication Module DoS (cisco-sa-20191002-ftd-fpmc-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a vulnerability in the configuration of the
Pluggable Authentication Module (PAM) due to improper resource management in the context of user session management. An
authenticated, remote attacker can exploit this, by connecting to an affected system and performing many simultaneous
successful Secure Shell (SSH) logins, in order to exhaust system resources and cause a denial of service (DoS)
condition.

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');
product_info['model'] = product_info['Model'];

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.101'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.155'},
  {'min_ver' : '2.4',  'fix_ver': '2.6.1.131'}
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
