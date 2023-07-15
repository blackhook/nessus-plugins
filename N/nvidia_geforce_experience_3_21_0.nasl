##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146428);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-1072");
  script_xref(name:"IAVA", value:"2021-A-0078-S");

  script_name(english:"NVIDIA GeForce Experience < 3.21.0 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A GPU companion application installed on the remote Windows host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA GeForce Experience installed on the remote Windows host is prior to 3.21.0. It is, therefore, 
affected by a denial of service vulnerability in GameStream (rxdiag.dll) due to improper handling of log files. An 
unauthenticated, local attacker can exploit this issue, where an arbitrary file deletion due to improper handling of 
log files may lead to denial of service.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5155");
  script_set_attribute(attribute:"solution", value:
"Update to NVIDIA GeForce Experience version 3.21.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1072");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:geforce_experience");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_geforce_experience_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/NVIDIA GeForce Experience");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'NVIDIA GeForce Experience', win_local:TRUE);

constraints = [
  { 'fixed_version' : '3.21.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
