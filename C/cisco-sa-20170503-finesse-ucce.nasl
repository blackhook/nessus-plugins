#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130093);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-6626");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc08314");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170503-finesse-ucce");

  script_name(english:"Cisco Finesse Information Disclosure (cisco-sa-20170503-finesse-ucce)");
  script_summary(english:"Checks the Cisco Finesse version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Finesse Software is affected by an information disclosure
vulnerability. This could allow an unauthenticated, remote attacker to retrieve information from agents using the
Finesse Desktop. The vulnerability is due to the existence of a user account that has an undocumented, hard-coded
password. An attacker could exploit this vulnerability by using the hard-coded credentials to subscribe to the Finesse
Notification Service, which would allow the attacker to receive notifications when an agent signs in or out of the
Finesse Desktop, when information about an agent changes, or when an agent's state changes.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-finesse-ucce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bfe00b0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc08314");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvc08314");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6626");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
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
  { 'min_version':'11.5.1', 'fixed_version':'11.5.2', 'fixed_display':'11.5(1)ES3, Bug ID: CSCvc08314', 'es_version':'3' },
  { 'min_version':'11.6.1', 'fixed_version':'11.6.2', 'fixed_display':'Refer to Bug ID: CSCvc08314' }
];

vcf::cisco_finesse::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
