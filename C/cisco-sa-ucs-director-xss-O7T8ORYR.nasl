#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139413);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/01");

  script_cve_id("CVE-2020-3464");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu08552");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucs-director-xss-O7T8ORYR");
  script_xref(name:"IAVA", value:"2020-A-0353");

  script_name(english:"Cisco UCS Director Stored Cross-Site Scripting Vulnerability (cisco-sa-ucs-director-xss-O7T8ORYR)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco UCS Director is affected by a vulnerability. Please see the included Cisco
BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucs-director-xss-O7T8ORYR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbdfde54");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu08552");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu08552");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3464");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/07");

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

constraints = [{'fixed_version': '6.7.4.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{'xss':TRUE});

