##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161395);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2021-4136",
    "CVE-2021-4166",
    "CVE-2021-4173",
    "CVE-2021-4187",
    "CVE-2021-4192",
    "CVE-2021-4193",
    "CVE-2021-44224",
    "CVE-2021-44790",
    "CVE-2021-45444",
    "CVE-2021-46059",
    "CVE-2022-0128",
    "CVE-2022-0530",
    "CVE-2022-0778",
    "CVE-2022-22589",
    "CVE-2022-22663",
    "CVE-2022-22665",
    "CVE-2022-22674",
    "CVE-2022-22675",
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23308",
    "CVE-2022-26697",
    "CVE-2022-26698",
    "CVE-2022-26706",
    "CVE-2022-26712",
    "CVE-2022-26714",
    "CVE-2022-26715",
    "CVE-2022-26718",
    "CVE-2022-26720",
    "CVE-2022-26721",
    "CVE-2022-26722",
    "CVE-2022-26723",
    "CVE-2022-26726",
    "CVE-2022-26728",
    "CVE-2022-26745",
    "CVE-2022-26746",
    "CVE-2022-26748",
    "CVE-2022-26751",
    "CVE-2022-26755",
    "CVE-2022-26756",
    "CVE-2022-26757",
    "CVE-2022-26761",
    "CVE-2022-26763",
    "CVE-2022-26766",
    "CVE-2022-26767",
    "CVE-2022-26768",
    "CVE-2022-26769",
    "CVE-2022-26770",
    "CVE-2022-26776"
  );
  script_xref(name:"IAVA", value:"2022-A-0212-S");
  script_xref(name:"IAVA", value:"2022-A-0442-S");
  script_xref(name:"APPLE-SA", value:"HT213256");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");

  script_name(english:"macOS 11.x < 11.6.6 Multiple Vulnerabilities (HT213256)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6.6 Big Sur. It is, therefore,
affected by multiple vulnerabilities including the following:

  - A logic issue in AppKit that may allow a malicious application to gain root privileges. (CVE-2022-22665)

  - A logic issue in Apache HTTP Server where it fails to close an inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling. (CVE-2022-22720)

  - A buffer overflow issue in the mod_lua component of Apache HTTP Server. (CVE-2021-44790)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT213256");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26770");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-26776");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();
var constraints = [{ 'min_version' : '11.0', 'fixed_version' : '11.6.6', 'fixed_display' : 'macOS Big Sur 11.6.6' }];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
