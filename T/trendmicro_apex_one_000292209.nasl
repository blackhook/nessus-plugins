#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173271);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2023-0587",
    "CVE-2023-25143",
    "CVE-2023-25144",
    "CVE-2023-25145",
    "CVE-2023-25146",
    "CVE-2023-25147",
    "CVE-2023-25148"
  );

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000292209)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to SP1 (Server Build 11564 and Agent Build 11564). It is, therefore, affected by multiple vulnerabilities:

  - An uncontrolled search path element vulnerability in the Trend Micro Apex One Server 
    installer could allow an attacker to achieve a remote code execution state on affected 
    products. (CVE-2023-25143)
    
  - An improper access control vulnerability in the Trend Micro Apex One agent could allow 
    a local attacker to gain elevated privileges and create arbitrary directories with 
    arbitrary ownership. (CVE-2023-25144)
    
  - A link following vulnerability in the scanning function of Trend Micro Apex One agent 
    could allow a local attacker to escalate privileges on affected installations. 
    (CVE-2023-25145)
    
  - A security agent link following vulnerability in the Trend Micro Apex One agent could 
    allow a local attacker to quarantine a file, delete the original folder and replace with 
    a junction to an arbitrary location, ultimately leading to an arbitrary file dropped to 
    an arbitrary location. (CVE-2023-25146)
    
  - An issue in the Trend Micro Apex One agent could allow an attacker who has previously 
    acquired administrative rights via other means to bypass the protection by using a 
    specifically crafted DLL during a specific update process. (CVE-2023-25147)
    
  - A security agent link following vulnerability in Trend Micro Apex One could allow a local 
    attacker to exploit the vulnerability by changing a specific file into a pseudo-symlink, 
    allowing privilege escalation on affected installations. (CVE-2023-25148)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000292209");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One SP1 (b11564/11564) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_one");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_apex_one_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Apex One");

  exit(0);
}

include('vcf.inc');

var app = 'Trend Micro Apex One';

var app_info = vcf::get_app_info(app:app, win_local:TRUE);

app_info.display_version = app_info.version;

var constraints = [{ 'fixed_version' : '14.0.0.11564' , 'fixed_display' : '14.0.0.11960 - Service Pack SP1 b11564'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
