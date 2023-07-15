#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126819);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id("CVE-2019-1576");
  script_bugtraq_id(109170);

  script_name(english:"Palo Alto Networks PAN-OS 9.0.x < 9.0.3 Vulnerability");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 9.0.x prior to 9.0.3. It is, therefore, affected
by a command injection vulnerability. An authenticated, remote attacker can exploit this to execute arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/156");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 9.0.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1576");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Host/Palo_Alto/Firewall/Source");

  exit(0);
}

include('vcf.inc');

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

constraints = [
  { 'min_version' : '9.0.0', 'max_version' : '9.0.2', 'fixed_version' : '9.0.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
