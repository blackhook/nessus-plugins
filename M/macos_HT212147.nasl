##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146086);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2019-20838",
    "CVE-2020-14155",
    "CVE-2020-15358",
    "CVE-2020-25709",
    "CVE-2020-27904",
    "CVE-2020-27937",
    "CVE-2020-27938",
    "CVE-2020-27945",
    "CVE-2020-29608",
    "CVE-2020-29614",
    "CVE-2020-29633",
    "CVE-2021-1736",
    "CVE-2021-1737",
    "CVE-2021-1738",
    "CVE-2021-1741",
    "CVE-2021-1742",
    "CVE-2021-1743",
    "CVE-2021-1744",
    "CVE-2021-1745",
    "CVE-2021-1746",
    "CVE-2021-1747",
    "CVE-2021-1750",
    "CVE-2021-1751",
    "CVE-2021-1753",
    "CVE-2021-1754",
    "CVE-2021-1757",
    "CVE-2021-1758",
    "CVE-2021-1759",
    "CVE-2021-1760",
    "CVE-2021-1761",
    "CVE-2021-1762",
    "CVE-2021-1763",
    "CVE-2021-1764",
    "CVE-2021-1765",
    "CVE-2021-1766",
    "CVE-2021-1767",
    "CVE-2021-1768",
    "CVE-2021-1769",
    "CVE-2021-1771",
    "CVE-2021-1772",
    "CVE-2021-1773",
    "CVE-2021-1774",
    "CVE-2021-1775",
    "CVE-2021-1776",
    "CVE-2021-1777",
    "CVE-2021-1778",
    "CVE-2021-1779",
    "CVE-2021-1782",
    "CVE-2021-1783",
    "CVE-2021-1785",
    "CVE-2021-1786",
    "CVE-2021-1787",
    "CVE-2021-1788",
    "CVE-2021-1789",
    "CVE-2021-1790",
    "CVE-2021-1791",
    "CVE-2021-1792",
    "CVE-2021-1793",
    "CVE-2021-1797",
    "CVE-2021-1799",
    "CVE-2021-1801",
    "CVE-2021-1802",
    "CVE-2021-1818",
    "CVE-2021-1870",
    "CVE-2021-1871"
  );
  script_xref(name:"APPLE-SA", value:"HT212147");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2021-02-01-1");
  script_xref(name:"IAVA", value:"2021-A-0058");
  script_xref(name:"IAVA", value:"2021-A-0505-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"macOS 10.14.x < 10.14.6 Security Update 2021-001 / 10.15.x < 10.15.7 Security Update 2021-001 / macOS 11.x < 11.2 (HT212147)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.14.x prior to 10.14.6 Security Update 2021-001
Mojave, 10.15.x prior to 10.15.7 Security Update 2021-001 Catalina, or 11.x prior to 11.2. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - A logic issue existed resulting in memory corruption. This was addressed with improved state management.
    An application may be able to execute arbitrary code with kernel privileges. (CVE-2020-27904)

  - A logic issue existed that allowed applications to execute arbitrary code with kernel privileges.
    (CVE-2021-1750)

  - An out-of-bounds-write caused by improper input validation allowed maliciously crafted USD files to
    unexpectedly terminate an application or cause arbitrary code execution. (CVE-2021-1762)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT212147");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.14.6 Security Update 2021-001 / 10.15.7 Security Update 2021-001 / macOS 11.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1779");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1871");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/03");

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

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G8012', 'fixed_display' : '10.14.6 Security Update 2021-001 Mojave' },
  { 'max_version' : '10.15.7', 'min_version' : '10.15', 'fixed_build': '19H512', 'fixed_display' : '10.15.7 Security Update 2021-001 Catalina' },
  { 'min_version' : '11.0', 'fixed_version' : '11.2', 'fixed_display' : 'macOS Big Sur 11.2' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
