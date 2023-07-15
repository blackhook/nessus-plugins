#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149986);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-36221",
    "CVE-2020-36222",
    "CVE-2020-36223",
    "CVE-2020-36224",
    "CVE-2020-36225",
    "CVE-2020-36226",
    "CVE-2020-36227",
    "CVE-2020-36228",
    "CVE-2020-36229",
    "CVE-2020-36230",
    "CVE-2021-21779",
    "CVE-2021-23841",
    "CVE-2021-30668",
    "CVE-2021-30669",
    "CVE-2021-30671",
    "CVE-2021-30673",
    "CVE-2021-30676",
    "CVE-2021-30677",
    "CVE-2021-30678",
    "CVE-2021-30679",
    "CVE-2021-30680",
    "CVE-2021-30681",
    "CVE-2021-30682",
    "CVE-2021-30683",
    "CVE-2021-30684",
    "CVE-2021-30685",
    "CVE-2021-30686",
    "CVE-2021-30687",
    "CVE-2021-30688",
    "CVE-2021-30689",
    "CVE-2021-30691",
    "CVE-2021-30692",
    "CVE-2021-30693",
    "CVE-2021-30694",
    "CVE-2021-30695",
    "CVE-2021-30696",
    "CVE-2021-30697",
    "CVE-2021-30698",
    "CVE-2021-30700",
    "CVE-2021-30701",
    "CVE-2021-30702",
    "CVE-2021-30704",
    "CVE-2021-30705",
    "CVE-2021-30707",
    "CVE-2021-30708",
    "CVE-2021-30709",
    "CVE-2021-30710",
    "CVE-2021-30712",
    "CVE-2021-30713",
    "CVE-2021-30715",
    "CVE-2021-30716",
    "CVE-2021-30717",
    "CVE-2021-30718",
    "CVE-2021-30719",
    "CVE-2021-30720",
    "CVE-2021-30721",
    "CVE-2021-30722",
    "CVE-2021-30723",
    "CVE-2021-30724",
    "CVE-2021-30725",
    "CVE-2021-30726",
    "CVE-2021-30727",
    "CVE-2021-30728",
    "CVE-2021-30734",
    "CVE-2021-30735",
    "CVE-2021-30736",
    "CVE-2021-30737",
    "CVE-2021-30738",
    "CVE-2021-30739",
    "CVE-2021-30740",
    "CVE-2021-30744",
    "CVE-2021-30746",
    "CVE-2021-30749"
  );
  script_xref(name:"APPLE-SA", value:"HT212529");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-05-25-2");
  script_xref(name:"IAVA", value:"2021-A-0251-S");
  script_xref(name:"IAVA", value:"2021-A-0349-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"macOS 11.x < 11.4 (HT212529)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.4 Big Sur. It is, therefore,
affected by multiple vulnerabilities including the following:

 - A remote attacker may be able to cause unexpected application termination or arbitrary code execution.
    (CVE-2021-30712)

  - A remote attacker may be able to cause unexpected application termination or arbitrary code execution.
    (CVE-2021-30678)

  - An application may be able to execute arbitrary code with kernel privileges. (CVE-2021-30704)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212529");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30740");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30678");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [{ 'min_version' : '11.0', 'fixed_version' : '11.4', 'fixed_display' : 'macOS Big Sur 11.4' }];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
