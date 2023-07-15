#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(170589);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/26");

  script_cve_id("CVE-2022-41085");

  script_name(english:"Security Updates for Azure CycleCloud (Nov 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Azure CycleCloud product is affected by a elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Azure CycleCloud product is missing security updates. 
It is, therefore, affected by an elevation of privilege vulnerability. An unauthenticated,
adjacent attacker can exploit this, via brute force authentication, to obtain a successful 
login and gain administrator privleges.

Note that Nessus has not tested for this issue but has instead relied 
only on the application's self-reported version number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-41085
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?119ad1d6");
  # https://learn.microsoft.com/en-us/azure/cyclecloud/release-notes/7-9-11?view=cyclecloud-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b3e43c2");
  # https://learn.microsoft.com/en-us/azure/cyclecloud/release-notes/8-3-0?view=cyclecloud-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d1a7597");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
        - CycleCloud version 7.9.11
        - CycleCloud version 8.3.0");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41085");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_cyclecloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("azure_cyclecloud_web_detect.nbin", "microsoft_azure_cyclecloud_web_detect.nbin");
  script_require_keys("installed_sw/Microsoft Azure CycleCloud");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Microsoft Azure CycleCloud', webapp:TRUE, port:port);

var constraints = [
  {'min_version': '0.0', 'fixed_version': '7.9.11'},
  {'min_version': '8.0', 'fixed_version': '8.3.0'}
];

vcf::check_version_and_report(
  app_info: app_info,
  constraints: constraints,
  severity: SECURITY_HOLE
);
