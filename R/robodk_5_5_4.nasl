#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174566);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2023-1516");

  script_name(english:"RoboDK < 5.5.4 Incorrect Permission Assignment");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RoboDK installed on the remote Windows host is prior to 5.5.4. It is, therefore, affected by a
vulnerability.

  - An insecure permission assignment to critical directories vulnerability,
    which could allow a local user to escalate privileges and write files to the
    RoboDK process and achieve code execution. (CVE-2023-1516)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisa.gov/news-events/ics-advisories/icsa-23-082-01");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RoboDK version 5.5.4 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:robodk:robodk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SCADA");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("robodk_win_installed.nbin");
  script_require_keys("installed_sw/RoboDK", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'RoboDK', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '5.5.4', 'fixed_display' : 'See vendor advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
