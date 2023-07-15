#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130013);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2015-6408");
  script_bugtraq_id(78875);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux24578");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151209-uc");

  script_name(english:"Cisco Unity Connection Cross-Site Request Forgery Vulnerability");
  script_summary(english:"Checks the Cisco Unity Connection version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cross-site request forgery (CSRF) vulnerability in Cisco Unity Connection 11.5(0.98)
allows remote attackers to hijack the authentication of arbitrary users.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151209-uc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00d45c01");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux24578");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCux24578");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6408");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

constraints = [
  { 'min_version':'11.5.0.98', 'fixed_version':'11.5.0.99', 'fixed_display':'See Advisory.' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xsrf:TRUE});
