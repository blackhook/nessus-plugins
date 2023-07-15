##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149094);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-24556",
    "CVE-2020-24557",
    "CVE-2020-24558",
    "CVE-2020-24562"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000263632)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to patch 3 b8378. It is, therefore, affected by multiple vulnerabilities:

  - A privilege escalation vulnerability in Trend Micro Apex One on Microsoft Windows may allow an attacker to
    create a hard link to any file on the system, which then could be manipulated to gain privilege escalation
    and code execution. An attacker must first obtain the ability to execute low-privileged code on the target
    system in order to exploit this vulnerability. Please note that version 1909 (OS Build 18363.719) of
    Microsoft Windows 10 mitigates hard links, but previous versions are affected. (CVE-2020-24556,
    CVE-2020-24562)

  - An improper access control privilege escalation in Trend Micro Apex One and OfficeScan XG SP1 on Microsoft
    Windows may allow an attacker to manipulate a particular product folder to disable the security
    temporarily, abuse a specific Windows function and attain privilege escalation. An attacker must first
    obtain the ability to execute low-privileged code on the target system in order to exploit this
    vulnerability. Please note that version 1909 (OS Build 18363.719) of Microsoft Windows 10 mitigates hard
    links, but previous versions are affected. (CVE-2020-24557)

  - An out-of-bounds read information disclosure vulnerability in Trend Micro Apex One and OfficeScan XG SP1
    dll may allow an attacker to manipulate it to cause an out-of-bounds read that crashes multiple processes
    in the product. An attacker must first obtain the ability to execute low-privileged code on the target
    system in order to exploit this vulnerability. (CVE-2020-24558)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/000263632");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One patch 3 b8378 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24562");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
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

app_info = vcf::get_app_info(app:'Trend Micro Apex One', win_local:TRUE);

constraints = [{ 'fixed_version' : '14.0.0.8378' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
