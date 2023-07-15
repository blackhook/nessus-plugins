#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130016);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/18 23:14:14");

  script_cve_id("CVE-2018-0354");
  script_bugtraq_id(104426);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf76417");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160203-uc");

  script_name(english:"Cisco Unity Connection Web Framework Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Unity Connection version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web framework of Cisco Unity Connection could allow an unauthenticated,
remote attacker to conduct a cross-site scripting (XSS) attack against the user of the web interface
of an affected system. The vulnerability is due to insufficient input validation of certain parameters
that are passed to the affected software via the HTTP GET and HTTP POST methods. An attacker who can
convince a user to follow an attacker-supplied link could execute arbitrary script or HTML code in the
user's browser in the context of an affected site.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180606-cuc-xss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2aa06cef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf76417");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvf76417");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0354");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

constraints = [
  { 'min_version':'12.5', 'fixed_version':'12.5.0.15', 'fixed_display':'See Advisory.' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
