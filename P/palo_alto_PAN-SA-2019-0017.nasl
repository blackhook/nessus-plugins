#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129502);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-8912");
  script_bugtraq_id(107063);

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.24 / 8.0.x < 8.0.18 / 8.1.x < 8.1.9 / 9.0.x < 9.0.3 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 7.1.x prior to 7.1.24 or 8.0.x prior to 8.0.18
or 8.1.x prior to 8.1.9 or 9.0.x prior to 9.0.3. It is, therefore, affected by a vulnerability.

- A privilege escalation vulnerability exists in the Linux kernel's sockfs_setattr. An unauthenticated, local attacker
  can exploit this to gain privileged access to the system.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/155");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 7.1.24 / 8.0.18 / 8.1.9 / 9.0.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8912");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include('vcf.inc');

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

constraints = [
  { 'min_version' : '7.1.0', 'max_version' : '7.1.23', 'fixed_display' : '7.1.24' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.17', 'fixed_display' : '8.0.18' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.8', 'fixed_display' : '8.1.9' },
  { 'min_version' : '9.0.0', 'max_version' : '9.0.2', 'fixed_display' : '9.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
