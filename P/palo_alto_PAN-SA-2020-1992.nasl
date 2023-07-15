#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137355);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1992");
  script_xref(name:"IAVA", value:"2020-A-0222-S");

  script_name(english:"Palo Alto Networks PAN-OS Series PA-7000 9.0 < 9.0.7 / 9.1 < 9.1.2 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 9.0.x prior to 9.0.7 or 9.1.x prior to 9.1.2.
It is, therefore, affected by a remote code execution vulnerability. Improper restriction of communications to Log
Forwarding Card (LFC) on PA-7000 Series devices with the WildFire service enabled may allow an unauthenticated attacker
with network access to the LFC to gain root access to PAN-OS.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.paloaltonetworks.com/CVE-2020-1992");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS 9.0.7, 9.1.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1992");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

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
include('vcf_extras.inc');

app_name = 'Palo Alto Networks PAN-OS';
vcf::palo_alto::initialize();

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');
model = get_kb_item_or_exit('Host/Palo_Alto/Firewall/Model');

if (  model !~ 'PA-7[0-9][0-9][0-9]($|[^0-9])') {
  audit(AUDIT_HOST_NOT, 'an affected model');
}

# We cannot test if LFS is installed and configured
if (report_paranoia < 2) audit(AUDIT_PARANOID);

constraints = [
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.7' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
