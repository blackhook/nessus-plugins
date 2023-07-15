#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153805);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/19");

  script_cve_id("CVE-2021-21569", "CVE-2021-21570");
  script_xref(name:"IAVA", value:"2021-A-0445-S");

  script_name(english:"Dell EMC NetWorker 18.x / 19.x < 19.4.0.4 Multiple Vulnerabilities (DSA-2021-124)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell EMC NetWorker installed on the remote Windows host is 18.x or 19.x prior to 19.4.0.4. It is,
therefore, affected by multiple vulnerabilities, as follows:

  - Dell NetWorker, versions 18.x and 19.x contain a Path traversal vulnerability. A NetWorker server user
    with remote access to NetWorker clients may potentially exploit this vulnerability and gain access to
    unauthorized information. (CVE-2021-21569)

  - Dell NetWorker, versions 18.x and 19.x contain an Information disclosure vulnerability. A NetWorker server
    user with remote access to NetWorker clients may potentially exploit this vulnerability and gain access to
    unauthorized information. (CVE-2021-21570)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.dell.com/support/kbdoc/en-ie/000188311/dsa-2021-124-dell-networker-security-update-for-multiple-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c83886");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell EMC NetWorker 19.4.0.4 or later. Alternatively, apply the mitigation steps outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21570");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:emc_networker");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_networker_installed.nasl");
  script_require_keys("installed_sw/EMC NetWorker", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'EMC NetWorker', win_local:TRUE);

var constraints = [
  { 'min_version' : '18.0', 'fixed_version' : '19.4.0.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);

