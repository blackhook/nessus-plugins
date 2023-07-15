#TRUSTED 1a329397c5ac2f36aa580056f2878ee1ca6d34ec577be769748dd26c9eeb6afc8b04dbcad877d27a3233a07a85d556e553e8c4f38518f348fd557aaeba8ddd6f0a519f72be954ddaa5b8b72c3f9349930854b488b7d31462948c93f9954f75789c661567d37fd30ee552723a478195486b845f0dd39a3eb246c13bf82868144708ae1dee7cf28e9a23b414dbee57d638b9fa24f7521ff74d2a0f39cc55b8c990e94bf15e5f4bf118c1eaaaf2fed4173160ebd8bb1aee6855030fe1aed534dd4ef1bfada31bf2d7547724ae6c9ddb4073b8721d7bf0120cd31401648b2ea2162b5cad81871d700f9b09aae5fe82ac1debc624e1c816b52ccc7a873128ae637977bcca07f31026d78c7fbdaabfdc956299b65318ef07ca182911c7bdb675e4d1434dc5390f3bd83d605d210ca14dcc8f3b43e665af36272fc7a48b043573868347c423d715daad3e68fd46294685e99c68dfa27e6cb03a53d015e378aaac41db718fb4c97840d8122130f90e7a21c647bdfcfa6e2a80f548bfa2c82ef625f1f832a7889815394231c7bede5da332b9af034d38b50daf406ae27611039b8868c6c1dd29991e5b59cbbd0a5fda4e123873033ce6d743da5be6725b0df38e6a6b22555d93af88e468fbe6d0c6239e5946069ad686cdb6a7413e7af8c4f82caff8ff7f0b49eb86b417ce0ea84ab4a85c2fff024d27fc4392c24c40e2225c3935960906
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132241);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-1858");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn19468");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-snmp-dos");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco FXOS Software Simple Network Management Protocol DoS (cisco-sa-20190515-nxos-snmp-dos)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a denial of service (DoS) vulnerability in
the Simple Network Management Protocol (SNMP) input packet processor due to improper error handling when processing
inbound SNMP packets. An unauthenticated, remote attacker can exploit this, by sending multiple crafted SNMP packets to
an affected device, to cause the SNMP application to leak system memory and, eventually, restart, resulting in a DoS
condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-snmp-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53871ca2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn19468");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn19468");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:fxos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

app_info = vcf::get_app_info(app:'FXOS');
# Get product_info to use Cisco functions for workaround check
product_info = make_array('model' , app_info['Model'], 'version' , app_info['version'], 'name', 'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
) audit(AUDIT_HOST_NOT, "affected");


vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2(2.91)'},
  {'min_ver' : '2.3',  'fix_ver': '2.3(1.130)'},
  {'min_ver' : '2.4',  'fix_ver': '2.4(1.222)'},
  {'min_ver' : '2.6',  'fix_ver': '2.6(1.131)'}
];


workarounds = make_list(CISCO_WORKAROUNDS['snmp']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvn19468',
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
