#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137134);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/08");

  script_cve_id("CVE-2020-3329");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs11314");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs35506");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvs35510");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucsd-Ar6BAguz");
  script_xref(name:"IAVA", value:"2020-A-0240");

  script_name(english:"Cisco UCS Director for Role-Based Access Control (cisco-sa-ucsd-Ar6BAguz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a role-based access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote host is running a version of Cisco UCS Director that is affected by
role-Based Access Control vulnerability. A remote authenticated attacker could exploit this vulnerability by  updating
the roles of other users to disable them. A successful exploit could allow the attacker to disable users, including
administrative users.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs11314");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs35506");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCvs35510");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucsd-Ar6BAguz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70e7a1d5");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ucs_director");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucs_director_detect.nbin");
  script_require_keys("Host/Cisco/UCSDirector/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco UCS Director', kb_ver:'Host/Cisco/UCSDirector/version');

# UCS Director releases 5.4.0.0 and later, earlier than Release 6.7.4.0
constraints = [
  { 'min_version' : '5.4.0.0', 'fixed_version': '6.7.4.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
