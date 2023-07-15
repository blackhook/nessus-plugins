##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143477);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/07");

  script_cve_id("CVE-2020-28421");
  script_xref(name:"IAVB", value:"2020-B-0072");

  script_name(english:"CA Unified Infrastructure Management Privilege Escalation (CA20201116-01)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number from the CA Unified Infrastructure Management (UIM) application running 
on the remote host is prior or equal to 9.0.2, 9.1.0, 9.2.0 or 20.x prior or equal to 20.1. It is, therefore, affected 
by a privilege escalation vulnerability in the robot component due to improper access control. A local attacker can
exploit this issue to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://support.broadcom.com/external/content/security-advisories/CA20201116-01-Security-Notice-for-CA-Unified-Infrastructure-Management/16565
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41848a35");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2020/Nov/41");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ca:unified_infrastructure_management");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:broadcom:unified_infrastructure_management");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ca_ump_detect.nbin");
  script_require_keys("installed_sw/CA UMP", "Settings/ParanoidReport");

  exit(0);
}
include('http.inc');
include('vcf.inc');

# Contains the version info we try to use
ump = 'CA UMP';

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:ump, port:port, webapp:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'max_version' : '9.0.2', 'fixed_display' : 'Refer to vendor advisory'},
  { 'equal' : '9.1.0', 'fixed_display' : 'Refer to vendor advisory'},
  { 'equal' : '9.2.0', 'fixed_display' : 'Refer to vendor advisory'},
  { 'min_version' : '20.0', 'max_version' : '20.1', 'fixed_display' : 'Refer to vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
