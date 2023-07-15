#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131699);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/09");

  script_cve_id("CVE-2019-1611");
  script_bugtraq_id(107381);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvk65447");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1611");

  script_name(english:"Cisco FXOS Software Command Injection (cisco-sa-20190306-nxos-cmdinj-1611)");
  script_summary(english:"Checks the version of Cisco FXOS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to certain CLI commands. An authenticated, local attacker with valid
administrator credentials can exploit this by including malicious input as the argument of an affected command in order
to execute arbitrary commands on the underlying operating system with elevated privileges.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1611
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?326bae04");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvk65447");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvk65447.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1611");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('vcf.inc');
include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = vcf::get_app_info(app:'FXOS');

# Use "Model" instead of "model"
if(
  isnull(product_info['Model']) ||
  product_info['Model'] !~ "^(41|93)[0-9]{2}$"
) audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

vuln_ranges =
  [
    { 'min_ver' : '0.0' ,'fix_ver' : '2.2.2.91'},
    { 'min_ver' : '2.3' ,'fix_ver' : '2.3.1.110'},
    { 'min_ver' : '2.4' ,'fix_ver' : '2.4.1.222'}
  ];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvk65447'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
