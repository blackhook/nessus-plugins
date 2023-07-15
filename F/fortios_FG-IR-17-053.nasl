#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124324);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id("CVE-2017-17544");
  script_bugtraq_id(107839);

  script_name(english:"Fortinet FortiGate <= 5.4.x / 5.6.x < 5.6.11 / 6.x < 6.2.0 Admin Privilege Escalation (FG-IR-17-053)");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a FortiOS version prior or equal to 5.4.x 
or 5.6.x prior to 5.6.11 or 6.x to 6.2.0. It is, therefore, affected 
by an elevation of privilege vulnerability. An authenticated, remote 
attacker with admin privileges can exploit this, via restoring a modified 
configuration, to gain elevated super_admin level privileges.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-17-053");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS version 5.6.11/6.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17544");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include('vcf.inc');
include('vcf_extras_fortios.inc');

app_name = "FortiOS";

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Fortigate/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::fortios::verify_product_and_model(product_name:'FortiGate');

constraints = [
  { "max_version" : "5.4.9999" , "fixed_version" : "5.6.11"}, # high max due to <= 5.4.x
  { "min_version" : "5.6.0" , "fixed_version" : "5.6.11"},
  { "min_version" : "6.0"   , "fixed_version" : "6.2.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
