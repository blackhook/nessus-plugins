#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176106);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-20182", "CVE-2023-20183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd58359");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd59863");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dnac-multiple-kTQkGU3");

  script_name(english:"Cisco DNA Center Multiple Vulnerabilities (cisco-sa-dnac-multiple-kTQkGU3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco DNA Center installed on the remote host is prior to 2.3.3.7 or 2.3.5.3. It is, therefore,
affected by multiple vulnerabilities:

  - Insufficient validation of user-supplied input in API request parameters. An authenticated, remote
    attacker can send specially crafted API request to an affected device to execute arbitrary commands in
    a restricted container as the root user. (CVE-2023-20182)

  - Due to improper authorization of API requests, a remote attacker with low privileges can send a specific
    API request to an affected device to enumerate limited information of users configured on the device.
    This information does not include passwords or password hashes. (CVE-2023-20183)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dnac-multiple-kTQkGU3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ecd7b7ca");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd58359");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd59863");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd58359, CSCwd59863");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:digital_network_architecture_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_dna_center_web_detect.nbin");
  script_require_keys("installed_sw/Cisco DNA Center");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Cisco DNA Center');

vcf::check_granularity(app_info:app_info, sig_segments:4);
var constraints = [
  {'fixed_version': '2.3.3.7'},
  {'min_version': '2.3.4', 'fixed_version': '2.3.5.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
