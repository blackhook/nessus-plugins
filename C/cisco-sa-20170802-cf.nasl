#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130094);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2017-6761");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd96744");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170802-cf");

  script_name(english:"Cisco Finesse Reflected Cross-Site Scripting Vulnerability (cisco-sa-20170802-cf)");
  script_summary(english:"Checks the Cisco Finesse version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Finesse Software is affected by a cross-site scripting vulnerability.
This could allow an unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of
the web-based management interface of an affected device. The vulnerability is due to insufficient validation of
user-supplied input by the web-based management interface of an affected device. An attacker could exploit this
vulnerability by persuading a user of the interface to click a crafted link. A successful exploit could allow the
attacker to execute arbitrary script code in the context of the interface or allow the attacker to access sensitive
browser-based information. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170802-cf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca8d7146");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd96744");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvd96744");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6761");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/02");
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
  { 'min_version':'10.6.1', 'fixed_version':'10.6.2', 'fixed_display':'Refer to Bug ID: CSCvd96744' },
  { 'min_version':'11.5.1', 'fixed_version':'11.5.2', 'fixed_display':'Refer to Bug ID: CSCvd96744' }
];

vcf::cisco_finesse::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
