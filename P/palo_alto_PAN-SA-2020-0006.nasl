#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136826);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2013-0337", "CVE-2016-4450");

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 8.1.14 / 8.0.x < 8.1.14 / 8.1.x < 8.1.14 / 9.0.x < 9.0.7 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 7.1.x prior to 8.1.14 or 8.0.x prior to 8.1.14 or
8.1.x prior to 8.1.14 or 9.0.x prior to 9.0.7. It is, therefore, affected by a vulnerability.

  - The default configuration of nginx, possibly 1.3.13 and earlier, uses world-readable 
    permissions for the (1) access.log and (2) error.log files, which allows local users 
    to obtain sensitive information by reading the files. (CVE-2013-0337)
  
  - os/unix/ngx_files.c in nginx before 1.10.1 and 1.11.x before 1.11.1 allows remote 
    attackers to cause a denial of service (NULL pointer dereference and worker process 
    crash) via a crafted request, involving writing a client request body to a temporary 
    file. (CVE-2016-4450)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.paloaltonetworks.com/PAN-SA-2020-0006");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 8.1.14 / 8.1.14 / 8.1.14 / 9.0.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0337");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-4450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version", "Host/Palo_Alto/Firewall/Source");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::palo_alto::initialize();

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', kb_source:'Host/Palo_Alto/Firewall/Source');

constraints = [
  { 'min_version' : '7.1.0', 'fixed_version' : '8.1.14' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.1.14' },
  { 'min_version' : '8.1.0', 'fixed_version' : '8.1.14' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
