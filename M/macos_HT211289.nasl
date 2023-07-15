#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141100);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2014-9512",
    "CVE-2019-14899",
    "CVE-2019-19906",
    "CVE-2019-20807",
    "CVE-2020-9799",
    "CVE-2020-9854",
    "CVE-2020-9863",
    "CVE-2020-9864",
    "CVE-2020-9865",
    "CVE-2020-9866",
    "CVE-2020-9868",
    "CVE-2020-9869",
    "CVE-2020-9870",
    "CVE-2020-9871",
    "CVE-2020-9872",
    "CVE-2020-9873",
    "CVE-2020-9874",
    "CVE-2020-9875",
    "CVE-2020-9876",
    "CVE-2020-9877",
    "CVE-2020-9878",
    "CVE-2020-9879",
    "CVE-2020-9880",
    "CVE-2020-9881",
    "CVE-2020-9882",
    "CVE-2020-9883",
    "CVE-2020-9884",
    "CVE-2020-9885",
    "CVE-2020-9887",
    "CVE-2020-9888",
    "CVE-2020-9889",
    "CVE-2020-9890",
    "CVE-2020-9891",
    "CVE-2020-9892",
    "CVE-2020-9898",
    "CVE-2020-9899",
    "CVE-2020-9900",
    "CVE-2020-9901",
    "CVE-2020-9902",
    "CVE-2020-9904",
    "CVE-2020-9905",
    "CVE-2020-9906",
    "CVE-2020-9908",
    "CVE-2020-9913",
    "CVE-2020-9918",
    "CVE-2020-9919",
    "CVE-2020-9920",
    "CVE-2020-9921",
    "CVE-2020-9924",
    "CVE-2020-9927",
    "CVE-2020-9928",
    "CVE-2020-9929",
    "CVE-2020-9934",
    "CVE-2020-9935",
    "CVE-2020-9936",
    "CVE-2020-9937",
    "CVE-2020-9938",
    "CVE-2020-9939",
    "CVE-2020-9940",
    "CVE-2020-9980",
    "CVE-2020-9984",
    "CVE-2020-9985",
    "CVE-2020-9990",
    "CVE-2020-9994",
    "CVE-2020-9997",
    "CVE-2020-11758",
    "CVE-2020-11759",
    "CVE-2020-11760",
    "CVE-2020-11761",
    "CVE-2020-11762",
    "CVE-2020-11763",
    "CVE-2020-11764",
    "CVE-2020-11765",
    "CVE-2020-12243"
  );
  script_xref(name:"IAVB", value:"2020-B-0053-S");
  script_xref(name:"APPLE-SA", value:"HT211289");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-07-15");
  script_xref(name:"IAVA", value:"2020-A-0539-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/29");

  script_name(english:"macOS 10.15.x < 10.15.6 / 10.14.x < 10.14.6 Security Update 2020-004 / 10.13.x < 10.13.6 Security Update 2020-004");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.13.x prior to 10.13.6 Security Update 2020-004,
10.14.x prior to 10.14.6 Security Update 2020-004, or 10.15.x prior to 10.15.6. It is, therefore, affected by multiple
vulnerabilities, including the following:

  - A vulnerability was discovered in Linux, FreeBSD, OpenBSD, MacOS, iOS, and Android that allows a malicious
    access point, or an adjacent user, to determine if a connected user is using a VPN, make positive
    inferences about the websites they are visiting, and determine the correct sequence and acknowledgement
    numbers in use, allowing the bad actor to inject data into the TCP stream. This provides everything that
    is needed for an attacker to hijack active connections inside the VPN tunnel. (CVE-2019-14899)

  - cyrus-sasl (aka Cyrus SASL) 2.1.27 has an out-of-bounds write leading to unauthenticated remote
    denial-of-service in OpenLDAP via a malformed LDAP packet. The OpenLDAP crash is ultimately caused by an
    off-by-one error in _sasl_add_string in common.c in cyrus-sasl. (CVE-2019-19906)

  - In Vim before 8.1.0881, users can circumvent the rvim restricted mode and execute arbitrary OS commands
    via scripting interfaces (e.g., Python, Ruby, or Lua). (CVE-2019-20807)

  - rsync 3.1.1 allows remote attackers to write to arbitrary files via a symlink attack on a file in the
    synchronization path. (CVE-2014-9512)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT211289");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macos 10.13.6 Security Update 2020-004 / 10.14.6 Security Update 2020-004 / 10.15.6 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.15.5', 'min_version' : '10.15', 'fixed_build': '19G73', 'fixed_display' : 'macOS Catalina 10.15.6' },
  { 'max_version' : '10.13.6', 'min_version' : '10.13', 'fixed_build': '17G14019', 'fixed_display' : '10.13.6 Security Update 2020-004' },
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G6020', 'fixed_display' : '10.14.6 Security Update 2020-004' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
