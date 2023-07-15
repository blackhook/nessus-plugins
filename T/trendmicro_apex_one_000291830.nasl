#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171389);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/14");

  script_cve_id("CVE-2022-45797", "CVE-2022-45798");

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000291830)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to SP1 (Server Build 11136 and Agent Build 11136). It is, therefore, affected by multiple vulnerabilities:

  - An arbitrary file deletion vulnerability in the Damage Cleanup Engine component of Trend Micro Apex One
    and Trend Micro Apex One as a Service could allow a local attacker to escalate privileges and delete files
    on affected installations. Please note: an attacker must first obtain the ability to execute
    low-privileged code on the target system in order to exploit this vulnerability. (CVE-2022-45797)

  - A link following vulnerability in the Damage Cleanup Engine component of Trend Micro Apex One and Trend
    Micro Apex One as a Service could allow a local attacker to escalate privileges by creating a symbolic
    link and abusing the service to delete a file. Please note: an attacker must first obtain the ability to
    execute low-privileged code on the target system in order to exploit this vulnerability. (CVE-2022-45798)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000291830?language=en_US");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One SP1 (b11136/11136) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45798");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_one");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_installed.nasl", "trendmicro_apex_one_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Apex One");

  exit(0);
}

include('vcf.inc');

var app = 'Trend Micro Apex One';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

app_info.display_version = app_info.version;

var constraints = [{ 'fixed_version' : '14.0.0.11136' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
