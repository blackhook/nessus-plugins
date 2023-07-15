#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130018);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/18 23:14:14");

  script_cve_id("CVE-2018-15396");
  script_bugtraq_id(105824);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj79033");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181003-unity-dos");

  script_name(english:"Cisco Unity Connection File Upload Denial of Service Vulnerability");
  script_summary(english:"Checks the Cisco Unity Connection version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Bulk Administration Tool (BAT) for Cisco Unity Connection could allow an authenticated,
remote attacker to cause high disk utilization, resulting in a denial of service (DoS) condition. The
vulnerability exists because the affected software does not restrict the maximum size of certain files that can
be written to disk. An attacker who has valid administrator credentials for an affected system could exploit this
vulnerability by sending a crafted, remote connection request to an affected system. A successful exploit could
allow the attacker to write a file that consumes most of the available disk space on the system, causing
application functions to operate abnormally and leading to a DoS condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-unity-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?547f4dfa");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj79033");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvj79033");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/03");
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
  { 'min_version':'12.5', 'fixed_version':'12.5.0.202', 'fixed_display':'See Advisory.' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
