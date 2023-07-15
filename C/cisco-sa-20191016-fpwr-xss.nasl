#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(130207);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/31");

  script_cve_id("CVE-2019-15280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55915");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55919");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55929");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55933");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55938");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55941");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55946");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55958");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq55967");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191016-fpwr-xss");

  script_name(english:"Cisco Firepower Management Center Software Stored Cross-Site Scripting (XSS) Vulnerability (cisco-sa-20191016-fpwr-xss)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Firepower Management Center is prior to 6.5.0. It is, therefore, 
affected by a cross-site scripting (XSS) vulnerability due to improper validation of user-supplied input before 
returning it to users. An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially 
crafted URL, to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # http://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20060922-understanding-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1596bcb6");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191016-fpwr-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bca3a19b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55915");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55919");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55929");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55933");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55938");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55941");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55946");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55958");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq55967");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvq55915, CSCvq55919, CSCvq55929, CSCvq55933,
CSCvq55938, CSCvq55941, CSCvq55946, CSCvq55958, CSCvq55967");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15280");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:firepower_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_firepower_version.nasl");
  script_require_keys("Host/Cisco/firepower_mc/version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco Firepower Management Center', kb_ver:'Host/Cisco/firepower_mc/version');
constraints = [{'fixed_version': '6.5.0'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags:{'xss':TRUE}
);
