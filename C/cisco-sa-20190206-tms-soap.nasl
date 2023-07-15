#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129947);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1660");
  script_bugtraq_id(106918);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj25332");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190206-tms-soap");

  script_name(english:"Cisco TelePresence Management Suite Simple Object Access Protocol Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Simple Object Access Protocol (SOAP) of Cisco
TelePresence Management Suite (TMS) software could allow an unauthenticated,
remote attacker to gain unauthorized access to an affected device.
The vulnerability is due to a lack of proper access and authentication
controls on the affected TMS software. An attacker could exploit this
vulnerability by gaining access to internal, trusted networks to send
crafted SOAP calls to the affected device. If successful, an exploit
could allow the attacker to access system management tools. Under normal
circumstances, this access should be prohibited.

Please see the included Cisco BIDs and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190206-tms-soap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2da1c4f7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj25332");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvj25332");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1660");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_management_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_management_suite_detect.nbin", "cisco_telepresence_management_suite_installed.nbin");
  script_require_keys("installed_sw/Cisco Telepresence Management Suite", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Cisco Telepresence Management Suite';
get_install_count(app_name:app, exit_if_zero:TRUE);
app_info = vcf::combined_get_app_info(app:app);

constraints = [{'min_version':'15.0', 'max_version':'15.7', 'fixed_display': 'Refer to Vendor Advisory'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
