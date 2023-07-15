#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129823);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2019-1860");
  script_bugtraq_id(108354);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo98208");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp65389");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-cuic-cmdinj");

  script_name(english:"Cisco Unified Intelligence Center Remote File Injection Vulnerability");
  script_summary(english:"Checks the Cisco Unified Intelligence Center (CUIC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the dashboard gadget rendering of Cisco Unified Intelligence Center could allow an
unauthenticated, remote attacker to obtain or manipulate sensitive information between a user's browser
and Cisco Unified Intelligence Center. The vulnerability is due to the lack of gadget validation.
An attacker could exploit this vulnerability by forcing a user to load a malicious gadget.
A successful exploit could allow the attacker to obtain sensitive information, such as current user
credentials, or manipulate data between the user's browser and Cisco Unified Intelligence Center in
the context of the malicious gadget.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-cuic-cmdinj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b9531ba2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo98208");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp65389");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvo98208 or CSCvp65389");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1860");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(99);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_intelligence_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_cuic_installed.nbin");
  script_require_keys("installed_sw/Cisco Unified Intelligence Center (CUIC)", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco Unified Intelligence Center (CUIC)');

# known affected releases: 12.0(1), version format is x.x.x.10000-xx
constraints = [
  { 'min_version':'12.0.1', 'fixed_version':'12.0.2', 'fixed_display':'Bug ID: CSCvo98208 or CSCvp65389' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
