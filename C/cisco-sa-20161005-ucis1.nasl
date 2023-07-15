#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129817);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2016-6425");
  script_bugtraq_id(93422);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy75020");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy81652");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161005-ucis1");

  script_name(english:"Cisco Unified Intelligence Center (CUIC) Software Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Unified Intelligence Center (CUIC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Cross-site scripting (XSS) vulnerability in Cisco Unified Intelligence Center (CUIC) 8.5.4 through 9.1(1),
as used in Unified Contact Center Express 10.0(1) through 11.0(1), allows remote attackers to inject arbitrary
web script or HTML via a crafted URL, aka Bug IDs CSCuy75020 and CSCuy81652.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ucis1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c12f011");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy75020");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy81652");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCuy75020 or CSCuy81652");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
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

# known affected releases: 8.5(4), 9.0(2), 9.1(1), 10.6(1), version format is x.x.x.10000-xx
constraints = [
  { 'min_version':'8.5.4', 'fixed_version':'8.5.5', 'fixed_display':'11.5(1.10000.22), Bug ID: CSCuy75020' },
  { 'min_version':'9.0.2', 'fixed_version':'9.0.3', 'fixed_display':'11.5(1.10000.22), Bug ID: CSCuy75020' },
  { 'min_version':'9.1.1', 'fixed_version':'9.1.2', 'fixed_display':'11.5(1.10000.22), Bug ID: CSCuy75020' },
  { 'min_version':'10.6.1', 'fixed_version':'10.6.2', 'fixed_display':'11.5(1.10000.61), Bug ID: CSCuy81652' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
