#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153429);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2013-0340",
    "CVE-2021-22925",
    "CVE-2021-30827",
    "CVE-2021-30828",
    "CVE-2021-30829",
    "CVE-2021-30830",
    "CVE-2021-30832",
    "CVE-2021-30841",
    "CVE-2021-30842",
    "CVE-2021-30843",
    "CVE-2021-30844",
    "CVE-2021-30845",
    "CVE-2021-30847",
    "CVE-2021-30850",
    "CVE-2021-30853",
    "CVE-2021-30855",
    "CVE-2021-30857",
    "CVE-2021-30858",
    "CVE-2021-30859",
    "CVE-2021-30860",
    "CVE-2021-30865",
    "CVE-2021-31010"
  );
  script_xref(name:"APPLE-SA", value:"HT212804");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-09-13-3");
  script_xref(name:"IAVA", value:"2021-A-0414-S");
  script_xref(name:"IAVA", value:"2021-A-0437-S");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/15");

  script_name(english:"macOS 11.x < 11.6 (HT212804)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.x prior to 11.6 Big Sur. It is, therefore,
affected by multiple vulnerabilities including the following:

  - A use after free issue was addressed with improved memory management. Exploitation of this vulnerability may lead to 
    arbitrary code execution. (CVE-2021-30858)

  - An integer overflow was addressed with improved input validation. Exploitation of this vulnerability may lead to 
    arbitrary code execution. (CVE-2021-30860)

  - Insufficient checks when processing maliciously crafted dfont files may lead to arbitrary code
    execution. (CVE-2021-30841, CVE-2021-30842, CVE-2021-30843)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-gb/HT212804");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30865");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-30858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/16");

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
var constraints = [{'min_version': '11.0', 'fixed_version': '11.6', 'fixed_display': 'macOS Big Sur 11.6'}];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
