#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149812);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id("CVE-2021-1519");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx86389");
  script_xref(name:"CISCO-SA", value:"cisco-sa-anyconnect-profile-AggMUCDg");
  script_xref(name:"IAVA", value:"2021-A-0243");

  script_name(english:"Cisco AnyConnect Secure Mobility Client Profile Modification Vulnerability (cisco-sa-anyconnect-profile-AggMUCDg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-anyconnect-profile-AggMUCDg)");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the cisco-sa-anyconnect-profile-AggMUCDg advisory. Note that Nessus has not tested for
this issue but has instead relied only on the application's self-reported version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-anyconnect-profile-AggMUCDg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d0a507c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx86389");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx86389");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1519");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', port:port, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);
constraints = [
  { 'fixed_version' : '4.10.00093.0', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
