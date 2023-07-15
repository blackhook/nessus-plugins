#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177128);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2022-33877");
  script_xref(name:"IAVA", value:"2023-A-0281");

  script_name(english:"Fortinet FortiClient (Windows) - Insecure Installation Folder (FG-IR-22-229)");

  script_set_attribute(attribute:"synopsis", value:
"remote Windows host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-229 advisory.

  - An incorrect default permissions [CWE-276] vulnerability in FortiClient (Windows) and FortiConverter
    (Windows) may allow a local authenticated attacker to tamper with files in the installation folder, if
    FortiClient or FortiConvreter is installed in an insecure folder. (CVE-2022-33877)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-229");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiClientWindows version 7.0.7 or above
Please upgrade to FortiClientWindows version 6.4.9 or above
Please upgrade to FortiConverter version 7.0.1 or above
Please upgrade to FortiConverter version 6.2.2 or above");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-33877");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include('vcf.inc');

var app_name = 'FortiClient';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '6.4.0', 'max_version' : '6.4.8', 'fixed_version' : '6.4.9' },
  { 'min_version' : '7.0.0', 'max_version' : '7.0.6', 'fixed_version' : '7.0.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
