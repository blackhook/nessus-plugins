##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161410);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/15");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2021-44224",
    "CVE-2021-44790",
    "CVE-2021-45444",
    "CVE-2022-0530",
    "CVE-2022-0778",
    "CVE-2022-22677",
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23308",
    "CVE-2022-26693",
    "CVE-2022-26694",
    "CVE-2022-26697",
    "CVE-2022-26698",
    "CVE-2022-26700",
    "CVE-2022-26701",
    "CVE-2022-26704",
    "CVE-2022-26706",
    "CVE-2022-26708",
    "CVE-2022-26709",
    "CVE-2022-26710",
    "CVE-2022-26711",
    "CVE-2022-26712",
    "CVE-2022-26714",
    "CVE-2022-26715",
    "CVE-2022-26716",
    "CVE-2022-26717",
    "CVE-2022-26718",
    "CVE-2022-26719",
    "CVE-2022-26720",
    "CVE-2022-26721",
    "CVE-2022-26722",
    "CVE-2022-26723",
    "CVE-2022-26725",
    "CVE-2022-26726",
    "CVE-2022-26727",
    "CVE-2022-26728",
    "CVE-2022-26731",
    "CVE-2022-26736",
    "CVE-2022-26737",
    "CVE-2022-26738",
    "CVE-2022-26739",
    "CVE-2022-26740",
    "CVE-2022-26741",
    "CVE-2022-26742",
    "CVE-2022-26743",
    "CVE-2022-26745",
    "CVE-2022-26746",
    "CVE-2022-26748",
    "CVE-2022-26749",
    "CVE-2022-26750",
    "CVE-2022-26751",
    "CVE-2022-26752",
    "CVE-2022-26753",
    "CVE-2022-26754",
    "CVE-2022-26755",
    "CVE-2022-26756",
    "CVE-2022-26757",
    "CVE-2022-26761",
    "CVE-2022-26762",
    "CVE-2022-26763",
    "CVE-2022-26764",
    "CVE-2022-26765",
    "CVE-2022-26766",
    "CVE-2022-26767",
    "CVE-2022-26768",
    "CVE-2022-26769",
    "CVE-2022-26770",
    "CVE-2022-26772",
    "CVE-2022-26775",
    "CVE-2022-26776"
  );
  script_xref(name:"APPLE-SA", value:"HT213257");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2022-05-16-2");
  script_xref(name:"IAVA", value:"2022-A-0212-S");
  script_xref(name:"IAVA", value:"2022-A-0442-S");

  script_name(english:"macOS 12.x < 12.4 (HT213257)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update or supplemental update that fixes multiple
vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 12.x prior to 12.4 Monterey. It is, therefore, 
affected by multiple vulnerabilities :

  - Exploitation of this vulnerability may lead to memory corruption issue. (CVE-2018-25032)

  - A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser. (CVE-2021-44790)

  - Exploitation of this vulnerability may lead to arbitrary code execution. (CVE-2021-45444)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-gb/HT213257");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26772");
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
var constraints = [
  {
    'min_version': '12.0', 
    'fixed_version': '12.4', 
    'fixed_display': 'macOS Monterey 12.4'
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
