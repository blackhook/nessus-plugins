#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131697);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/09");

  script_cve_id("CVE-2019-1795");
  script_bugtraq_id(108479);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvh66259");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-nxos-cmdinj-1795");

  script_name(english:"Cisco FXOS Software Command Injection (cisco-sa-20190515-nxos-cmdinj-1795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by a command injection vulnerability due to
insufficient validation of arguments passed to a specific CLI command on an affected device. An authenticated, local
attacker can exploit this to execute arbitrary commands on the underlying Linux operating system with root privileges.

Please see the included Cisco BID and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-nxos-cmdinj-1795
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9ac45f1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvh66259");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvh66259");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1795");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower");
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

app_info = vcf::get_app_info(app:'FXOS');

if(
  isnull(app_info['Model']) ||
  app_info['Model'] !~ "^(41|93)[0-9]{2}$"
) audit(AUDIT_HOST_NOT, 'affected');

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

vuln_ranges =
  [
    { 'min_ver' : '0.0' ,'fix_ver' : '2.0.1.201'},
    { 'min_ver' : '2.1' ,'fix_ver' : '2.2.2.54'},
    { 'min_ver' : '2.3' ,'fix_ver' : '2.3.1.73'},
    { 'min_ver' : '2.4' ,'fix_ver' : '2.4.1.101'}
  ];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , app_info['version'],
  'bug_id'   , 'CSCvh66259'
);

cisco::check_and_report(
  product_info:app_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
