#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130015);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/18 23:14:14");

  script_cve_id("CVE-2015-6360");
  script_bugtraq_id(85793);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux35568");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-libsrtp");

  script_name(english:"Cisco Unity Connection libSRTP Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco Unity Connection version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The encryption-processing feature in Cisco libSRTP before 1.5.3 allows remote attackers to cause a denial of
service via crafted fields in SRTP packets.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-libsrtp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2658d700");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux35568");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCux35568");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/20");
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
  { 'min_version':'10.5', 'fixed_version':'10.5.2.13900.12', 'fixed_display':'10.5(2)SU3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
