##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149043);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2020-3838",
    "CVE-2020-8037",
    "CVE-2020-8285",
    "CVE-2020-8286",
    "CVE-2020-27942",
    "CVE-2021-1739",
    "CVE-2021-1784",
    "CVE-2021-1797",
    "CVE-2021-1805",
    "CVE-2021-1806",
    "CVE-2021-1808",
    "CVE-2021-1809",
    "CVE-2021-1811",
    "CVE-2021-1813",
    "CVE-2021-1828",
    "CVE-2021-1834",
    "CVE-2021-1839",
    "CVE-2021-1840",
    "CVE-2021-1843",
    "CVE-2021-1847",
    "CVE-2021-1851",
    "CVE-2021-1857",
    "CVE-2021-1860",
    "CVE-2021-1868",
    "CVE-2021-1873",
    "CVE-2021-1875",
    "CVE-2021-1876",
    "CVE-2021-1878",
    "CVE-2021-1881",
    "CVE-2021-30652"
  );
  script_xref(name:"APPLE-SA", value:"HT212327");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-04-26-4");
  script_xref(name:"IAVA", value:"2021-A-0202-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"macOS 10.14.x < 10.14.6 Security Update 2021-003 Mojave (HT212327)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior to 10.14.6 Security Update 2021-003 Mojave
It is, therefore, affected by multiple vulnerabilities, including the following:

  - An application may be able to execute arbitrary code with system privileges due to insufficient permission
    checks (CVE-2020-3838).

  - A memory corruption vulnerability could allow an application read access to restricted memory (CVE-2021-1808).

  - A memory corruption vulnerability could allow an application to cause unexpected system termination or to 
    write kernel memory (CVE-2021-1828).

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212327");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.14.6 Security Update 2021-003 Mojave or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1834");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 
    'max_version' : '10.14.6', 
    'min_version' : '10.14', 
    'fixed_build': '18G9028', 
    'fixed_display' : '10.14.6 Security Update 2021-003 Mojave' 
  }
];

vcf::apple::macos::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);
