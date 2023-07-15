#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164982);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2022-40139",
    "CVE-2022-40140",
    "CVE-2022-40141",
    "CVE-2022-40142",
    "CVE-2022-40143",
    "CVE-2022-40144"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/06");
  script_xref(name:"CEA-ID", value:"CEA-2022-0030");

  script_name(english:"Trend Micro Apex One Multiple Vulnerabilities (000291528)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Trend Micro application running on the remote Windows host is Apex One
prior to SP1 (Server Build 11092 and Agent Build 11088). It is, therefore, affected by multiple vulnerabilities:

  - Improper validation of some components used by the rollback mechanism in Trend Micro Apex One and Trend Micro Apex
    One as a Service clients could allow a Apex One server administrator to instruct affected clients to download an
    unverified rollback package, which could lead to remote code execution. (CVE-2022-40139)

  - An origin validation error vulnerability in Trend Micro Apex One and Apex One as a Service could allow a local
    attacker to cause a denial-of-service on affected installations. (CVE-2022-40140)

  - A vulnerability in Trend Micro Apex One and Apex One as a Service could allow an attacker to intercept and decode
    certain communication strings that may contain some identification attributes of a particular Apex One server.
    (CVE-2022-40141)

  - A security link following local privilege escalation vulnerability in Trend Micro Apex One and Trend Micro Apex One
    as a Service agents could allow a local attacker to create a writable folder in an arbitrary location and escalate
    privileges on affected installations. (CVE-2022-40142)

  - A link following local privilege escalation vulnerability in Trend Micro Apex One and Trend Micro Apex One as a
    Service servers could allow a local attacker to abuse an insecure directory that could allow a low-privileged user
    to run arbitrary code with elevated privileges. (CVE-2022-40143)

  - A vulnerability in Trend Micro Apex One and Trend Micro Apex One as a Service could allow an attacker to bypass the
    product's login authentication by falsifying request parameters on affected installations. (CVE-2022-40144)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/dcx/s/solution/000291528?language=en_US");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apex One SP1 (b11092/11088) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-40144");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:apex_one");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_installed.nasl");
  script_require_keys("installed_sw/Trend Micro Apex One");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Trend Micro Apex One', win_local:TRUE);

var constraints = [{ 'fixed_version' : '14.0.0.11088' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
