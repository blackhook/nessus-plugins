#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171153);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2022-31611", "CVE-2022-42291", "CVE-2022-42292");
  script_xref(name:"IAVA", value:"2023-A-0070");

  script_name(english:"NVIDIA GeForce Experience < 3.27.0.112 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A GPU companion application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of NVIDIA GeForce Experience installed on the remote host is prior to 3.24.0.126. It is, therefore,
affected by multiple vulnerabilities:

 - A vulnerability in the installer, where a user installing the NVIDIA GeForce Experience software may
   inadvertently delete data from a linked location, which may lead to data tampering. An attacker does not
   have explicit control over the exploitation of this vulnerability which requires the user to explicitly
   launch the installer from a compromised directory. (CVE-2022-42291)

 - An uncontrolled search path vulnerability in all its client installers where an attacker with user
   level privileges may cause the installer to load an arbitrary DLL when the installer is launched. A
   successful exploitation of this vulnerability could lead to escalation of privileges and code execution.
   (CVE-2022-31611)

 - A vulnerability in the NVContainer component where a user without administrative privileges can create a
   symbolic link to a file that requires elevated privileges to write or modify. Successful exploitation of
   this vulnerability can lead to denial of service, escalation of privilege or data tampering.
   (CVE-2022-42292)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5384");
  script_set_attribute(attribute:"solution", value:
"Update to NVIDIA GeForce Experience version 3.27.0.112 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42292");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:geforce_experience");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_geforce_experience_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/NVIDIA GeForce Experience");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'NVIDIA GeForce Experience', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '3.27.0.112' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
