#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133531);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2019-11043",
    "CVE-2019-18634",
    "CVE-2020-3826",
    "CVE-2020-3827",
    "CVE-2020-3829",
    "CVE-2020-3830",
    "CVE-2020-3835",
    "CVE-2020-3836",
    "CVE-2020-3837",
    "CVE-2020-3838",
    "CVE-2020-3839",
    "CVE-2020-3840",
    "CVE-2020-3842",
    "CVE-2020-3843",
    "CVE-2020-3845",
    "CVE-2020-3846",
    "CVE-2020-3847",
    "CVE-2020-3848",
    "CVE-2020-3849",
    "CVE-2020-3850",
    "CVE-2020-3853",
    "CVE-2020-3854",
    "CVE-2020-3855",
    "CVE-2020-3856",
    "CVE-2020-3857",
    "CVE-2020-3866",
    "CVE-2020-3870",
    "CVE-2020-3871",
    "CVE-2020-3872",
    "CVE-2020-3875",
    "CVE-2020-3877",
    "CVE-2020-3878"
  );
  script_xref(name:"APPLE-SA", value:"HT210919");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2020-01-23");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"macOS 10.15.x < 10.15.3 / 10.14.x < 10.14.6 / 10.13.x < 10.13.6");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a MacOS update which fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 10.15.x prior to 10.15.3, 
10.13.x prior to 10.13.6, 10.14.x prior to 10.14.6. It is, therefore, affected by multiple
vulnerabilities:

  - In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24
    and 7.3.x below 7.3.11 in certain configurations of FPM
    setup it is possible to cause FPM module to write past
    allocated buffers into the space reserved for FCGI
    protocol data, thus opening the possibility of remote
    code execution. (CVE-2019-11043)

  - An arbitrary code exution vulnerability exists  
    due to a misconfiguration. An authenticated, local attacker 
    can exploit this to execute arbitrary code on the remote host.
    (CVE-2019-18634)

  - An arbitrary code exution vulnerability exists  
    due to the ability to process a maliciously crafted image. 
    An unauthenticated, remote attacker can exploit this to 
    execute arbitrary code on the remote host.
    (CVE-2020-3826 CVE-2020-3827 CVE-2020-3870 CVE-2020-3878)

  - A privilege escalation vulnerability exists in due to an out-of-bounds read issue. 
    An unauthenticated, remote attacker can exploit this, to gain elevated
    access to the system. (CVE-2020-3829)

  - An arbitrary file write vulnerability exists in the handling of symlinks. 
    A malicious program crafted by an attacker can exploit this to overwrite arbitrary files on the remote host.
    (CVE-2020-3830 CVE-2020-3835 CVE-2020-3855)

  - An information disclosure vulnerability exists in the access control handling of applications. 
    A malicious application crafted by attacker can exploit this to disclose the kernel memory layout.
    (CVE-2020-3836)

  - An arbitrary code exution vulnerability exists  
    due to a memory corruption issue. A malicious application 
    crafted by a remote attacker may be able to execute arbitrary code 
    with kernel privileges on the remote host.
    (CVE-2020-3837  CVE-2020-3842 CVE-2020-3871)

  - An arbitrary code exution vulnerability exists  
    due to a permissions logic flaw.  A malicious application 
    crafted by a remote attacker may be able to execute arbitrary code 
    with system privileges on the remote host.
    (CVE-2019-18634 CVE-2020-3854 CVE-2020-3845 CVE-2020-3853 CVE-2020-3857)

  - An information disclosure vulnerability exists in the input sanitization logic. 
    A malicious application crafted by attacker can exploit this to read restricted memory.
    (CVE-2020-3839 CVE-2020-3847)

  - An arbitrary code exution vulnerability exists  
    due to the loading of a maliciously crafted racoon configuration file. 
    An authenticated, local attacker can exploit this to execute arbitrary code on the remote host.
    (CVE-2020-3840)

  - A denial of service (DoS) vulnerability exists due to a memory corruption issue. An 
    unauthenticated, remote attacker can exploit this issue, via malicious input, to cause the 
    system to crash, stop responding, or corrupt the kernel memory. (CVE-2020-3843)

  - An arbitrary code exution vulnerability exists  
    due to either a buffer overflow or out-of-bounds read issue. An authenticated, local attacker 
    can exploit this to execute arbitrary code on the remote host or 
    cause an unexpected application to terminate.
    (CVE-2020-3846 CVE-2020-3848 CVE-2020-3849 CVE-2020-3850 CVE-2020-3877)

  - A memory corruption vulnerability exists due to a malicious crafted string. An 
    unauthenticated, remote attacker can exploit this issue, via malicious input, to cause the 
    corruption of the heap memory. (CVE-2020-3856)

  - An security bypass vulnerability exists in the handling of files from an attacker controlled NFS mount. 
    A remote attacker with local access could search for and open a file from an attacker controlled NFS mount
    and bypass Gatekeeper Security features. (CVE-2020-3866)

  - An information disclosure vulnerability exists where an application 
    can read restricted memory.  A local, authorized attacker can exploit this to read restricted memory.
    (CVE-2020-3872 CVE-2020-3875)

Note that Nessus has not tested for this issue but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210919");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 10.13.6, 10.14.6, 10.15.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3847");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-3850");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras_apple.inc');

app_info = vcf::apple::macos::get_app_info();

constraints = [
  { 'max_version' : '10.13.6', 'min_version' : '10.13', 'fixed_build': '17G11023', 'fixed_display' : '10.13.6 Security Update 2020-001' },
  { 'max_version' : '10.14.6', 'min_version' : '10.14', 'fixed_build': '18G3020', 'fixed_display' : '10.14.6 Security Update 2020-001' },
  { 'max_version' : '10.15.2', 'min_version' : '10.15', 'fixed_build': '19D76', 'fixed_display' : '10.15.3 MacOS Catalina 10.15.3' }
];

vcf::apple::macos::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

