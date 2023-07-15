#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168650);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2022-22950");

  script_name(english:"Dell EMC NetWorker < 19.8 DoS (DSA-2022-350)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC NetWorker installed on the remote Windows host is prior to 19.8. It, therefore, contains a
version of Spring Framework that is affected by a denial of service (DoS) vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000206132/dsa-2022-350-dell-networker-security-update-for-spring-framework-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f8a39c1");
  script_set_attribute(attribute:"solution", value:
"Upgrade Dell EMC Networker to 19.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22950");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '19.7', 'fixed_display': '19.8' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

