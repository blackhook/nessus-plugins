#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130095);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-12337");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg64475");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171115-vos");

  script_name(english:"Cisco Finesse Unauthorized Access (cisco-sa-20171115-vos)");
  script_summary(english:"Checks the Cisco Finesse version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Finesse Software is affected by an unauthorized access
vulnerability. The vulnerability in the upgrade mechanism of Cisco collaboration products based on the Cisco Voice 
Operating System software platform could allow an unauthenticated, remote attacker to gain unauthorized, elevated access
to an affected device. The vulnerability occurs when a refresh upgrade (RU) or Prime Collaboration Deployment (PCD) 
migration is performed on an affected device. When a refresh upgrade or PCD migration is completed successfully, 
an engineering flag remains enabled and could allow root access to the device with a known password.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171115-vos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e2c1cc2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvg64475");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvg64475");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12337");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:finesse");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_finesse_installed.nbin");
  script_require_keys("installed_sw/Cisco VOSS Finesse", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_finesse::get_app_info(app:'Cisco VOSS Finesse');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'min_version':'11.0', 'fixed_version':'11.1', 'required_cop':'CSCvg55145', 'fixed_display':'COP file: ucos-psirt-root-access-CSCvg55145-k3-1.1.cop, Bug ID: CSCvg64475' },
  { 'min_version':'11.5', 'fixed_version':'11.7', 'required_cop':'CSCvg55145', 'fixed_display':'COP file: ucos-psirt-root-access-CSCvg55145-k3-1.1.cop, Bug ID: CSCvg64475' }
];

vcf::cisco_finesse::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
