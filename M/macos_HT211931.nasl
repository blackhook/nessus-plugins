##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143115);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-14899",
    "CVE-2019-20838",
    "CVE-2020-9849",
    "CVE-2020-9876",
    "CVE-2020-9883",
    "CVE-2020-9941",
    "CVE-2020-9942",
    "CVE-2020-9943",
    "CVE-2020-9944",
    "CVE-2020-9945",
    "CVE-2020-9949",
    "CVE-2020-9955",
    "CVE-2020-9963",
    "CVE-2020-9965",
    "CVE-2020-9966",
    "CVE-2020-9969",
    "CVE-2020-9971",
    "CVE-2020-9974",
    "CVE-2020-9977",
    "CVE-2020-9988",
    "CVE-2020-9989",
    "CVE-2020-9991",
    "CVE-2020-9996",
    "CVE-2020-9999",
    "CVE-2020-10002",
    "CVE-2020-10003",
    "CVE-2020-10004",
    "CVE-2020-10006",
    "CVE-2020-10007",
    "CVE-2020-10008",
    "CVE-2020-10009",
    "CVE-2020-10010",
    "CVE-2020-10012",
    "CVE-2020-10014",
    "CVE-2020-10016",
    "CVE-2020-10017",
    "CVE-2020-10663",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13524",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-14155",
    "CVE-2020-15358",
    "CVE-2020-27894",
    "CVE-2020-27896",
    "CVE-2020-27898",
    "CVE-2020-27899",
    "CVE-2020-27900",
    "CVE-2020-27903",
    "CVE-2020-27904",
    "CVE-2020-27906",
    "CVE-2020-27910",
    "CVE-2020-27911",
    "CVE-2020-27912",
    "CVE-2020-27916",
    "CVE-2020-27917",
    "CVE-2020-27918",
    "CVE-2020-27927",
    "CVE-2020-27930",
    "CVE-2020-27932",
    "CVE-2020-27950"
  );
  script_xref(name:"APPLE-SA", value:"HT211931");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-11-12");
  script_xref(name:"IAVA", value:"2020-A-0539-S");
  script_xref(name:"IAVA", value:"2020-A-0576-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"macOS 11.0.x < 11.0.1");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 11.0.x prior to 11.0.1. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - An out-of-bounds write issue that can lead to unexpected application termination or arbitrary code
    execution when opening a maliciously crafted PDF file. (CVE-2020-9876)

  - An out-of-bounds write caused by insufficient input validation that can lead to arbitrary code execution
    when processing a maliciously crafted image. (CVE-2020-9883)

  - A remote attacker may be able to unexpectedly alter the Mail application date due to insufficient checks.
    (CVE-2020-9941)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211931");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 11.0.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9965");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-27906");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.0.1',  'fixed_build': '20B29', 'fixed_display' : 'macOS Big Sur 11.0.1' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
