##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148137);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/18");

  script_cve_id(
    "CVE-2021-1411",
    "CVE-2021-1417",
    "CVE-2021-1418",
    "CVE-2021-1469",
    "CVE-2021-1471"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw96073");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw96075");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw96079");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx36433");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx43270");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cisco-jabber-PWrTATTC");
  script_xref(name:"IAVA", value:"2021-A-0142-S");

  script_name(english:"Cisco Jabber Multiple Vulnerabilities (cisco-sa-cisco-jabber-PWrTATTC)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Jabber is affected by multiple vulnerabilities which could allow a 
remote, authenticated attacker to execute arbitrary programs on the underlying operating system with the
privileges of the user account that is running the Cisco Jabber client software or gain access to sensitive
information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cisco-jabber-PWrTATTC
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?907b8da4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw96073");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw96075");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw96079");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx36433");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx43270");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the relevant Cisco Security Advisory");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1411");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_jabber_client_installed.nbin", "macosx_cisco_jabber_for_mac_installed.nbin");
  script_require_ports("installed_sw/Cisco Jabber for Windows", "installed_sw/Cisco Jabber");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated'))
{
  app_info = vcf::get_app_info(app:'Cisco Jabber for Windows', win_local:TRUE);

  constraints = [
    { 'min_version' : '0.0 ', 'fixed_version' : '12.1.5'},
    { 'min_version' : '12.5 ', 'fixed_version' : '12.5.4'},
    { 'min_version' : '12.6 ', 'fixed_version' : '12.6.5'},
    { 'min_version' : '12.7 ', 'fixed_version' : '12.7.4'},
    { 'min_version' : '12.8 ', 'fixed_version' : '12.8.5'},
    { 'min_version' : '12.9 ', 'fixed_version' : '12.9.5'}
  ];
}
else
{
  app_info = vcf::get_app_info(app:'Cisco Jabber', win_local:FALSE);

  constraints = [
    { 'min_version' : '0.0 ', 'fixed_version' : '12.8.7'},
    { 'min_version' : '12.9 ', 'fixed_version' : '12.9.6'}
  ];
}

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
