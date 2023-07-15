#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154960);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2021-32464",
    "CVE-2021-32465",
    "CVE-2021-36741",
    "CVE-2021-36742"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000287819)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to patch 3 b9601. It is, therefore, affected by multiple vulnerabilities:

  - An incorrect permission assignment privilege escalation vulnerability in Trend Micro Apex One and Apex
    One as a Service could allow an attacker to modify a specific script before it is executed. 
    (CVE-2021-32464)  

  - An incorrect permission preservation vulnerability in Trend Micro Apex One and Apex One as a Service 
    could allow a remote user to perform an attack and bypass authentication on affected installations. 
    (CVE-2021-32465)

  - An improper input validation vulnerability in Trend Micro Apex One and Apex One as a Service allows a 
    remote attached to upload arbitrary files on affected installations. (CVE-2021-36741)

  - A improper input validation vulnerability in Trend Micro Apex One and Apex One as a Service allows a 
    local attacker to escalate privileges on affected installations. (CVE-2021-36742)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/000287819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One patch 3 b9601 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32464");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-36741");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_one");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("installed_sw/Trend Micro Apex One");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Trend Micro Apex One', win_local:TRUE);

var constraints = [{ 'fixed_version' : '14.0.0.9601' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
