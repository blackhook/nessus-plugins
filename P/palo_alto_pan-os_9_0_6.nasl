#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133858);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-1975");
  script_xref(name:"IAVA", value:"2019-A-0077-S");

  script_name(english:"Palo Alto Networks PAN-OS  8.1.x < 8.1.12 /  9.0.x < 9.0.6 Privilege Escalation Vulnerability");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host
is 8.1.x prior to 8.1.12 or 9.0.x prior to 9.0.6. It is, therefore, 
affected by a privilege escalation vulnerability.");
  # https://security.paloaltonetworks.com/CVE-2020-1975
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05e454ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 8.1.12 / 9.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('http_func.inc');

app_name = "Palo Alto Networks PAN-OS";
port = get_http_port(default:443);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Palo_Alto/Firewall/Full_Version", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "8.1", "fixed_version" : "8.1.12" },
  { "min_version" : "9.0", "fixed_version" : "9.0.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
