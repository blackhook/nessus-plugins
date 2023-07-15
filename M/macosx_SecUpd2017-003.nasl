#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101957);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2016-9586",
    "CVE-2016-9594",
    "CVE-2017-2629",
    "CVE-2017-7008",
    "CVE-2017-7009",
    "CVE-2017-7010",
    "CVE-2017-7013",
    "CVE-2017-7014",
    "CVE-2017-7015",
    "CVE-2017-7016",
    "CVE-2017-7017",
    "CVE-2017-7021",
    "CVE-2017-7022",
    "CVE-2017-7023",
    "CVE-2017-7024",
    "CVE-2017-7025",
    "CVE-2017-7026",
    "CVE-2017-7027",
    "CVE-2017-7028",
    "CVE-2017-7029",
    "CVE-2017-7031",
    "CVE-2017-7032",
    "CVE-2017-7033",
    "CVE-2017-7035",
    "CVE-2017-7036",
    "CVE-2017-7044",
    "CVE-2017-7045",
    "CVE-2017-7047",
    "CVE-2017-7050",
    "CVE-2017-7051",
    "CVE-2017-7054",
    "CVE-2017-7062",
    "CVE-2017-7067",
    "CVE-2017-7068",
    "CVE-2017-7069",
    "CVE-2017-7468",
    "CVE-2017-9417"
  );
  script_bugtraq_id(
    95019,
    95094,
    96382,
    97962,
    99482,
    99879,
    99880,
    99882,
    99883,
    99889
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-05-15-1");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2017-003)");
  script_summary(english:"Checks for the presence of Security Update 2017-003.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.10.5, Mac OS X 10.11.6, or
macOS 10.12.5 and is missing a security update. It is therefore,
affected by multiple vulnerabilities :

  - An overflow condition exists in the curl component in
    the dprintf_formatf() function that is triggered when
    handling floating point conversion. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-9586)

  - A flaw exits in the curl component in the randit()
    function within file lib/rand.c due to improper
    initialization of the 32-bit random value, which is
    used, for example, to generate Digest and NTLM
    authentication nonces, resulting in weaker cryptographic
    operations than expected. (CVE-2016-9594)

  - A flaw exists in the curl component in the
    allocate_conn() function in lib/url.c when using the
    OCSP stapling feature for checking a X.509 certificate
    revocation status. The issue is triggered as the request
    option for OCSP stapling is not properly passed to the
    TLS library, resulting in no error being returned even
    when no proof of the validity of the certificate could
    be provided. A man-in-the-middle attacker can exploit
    this to provide a revoked certificate. (CVE-2017-2629)

  - A remote code execution vulnerability exists in the
    CoreAudio component due to improper validation of
    user-supplied input when handling movie files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to play a specially crafted movie
    file, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-7008)

  - A memory corruption issue exists in the IOUSBFamily
    component due to improper validation of user-supplied
    input. A local attacker can exploit this, via a
    specially crafted application, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-7009)

  - Multiple out-of-bounds read errors exist in the libxml2
    component due to improper handling of specially crafted
    XML documents. An unauthenticated, remote attacker can
    exploit these to disclose user information.
    (CVE-2017-7010, CVE-2017-7013)

  - Multiple memory corruption issues exist in the Intel
    Graphics Driver component due to improper validation of
    input. A local attacker can exploit these issues to
    execute arbitrary code with elevated privileges.
    (CVE-2017-7014, CVE-2017-7017, CVE-2017-7035,
    CVE-2017-7044)

  - A remote code execution vulnerability exists in the
    Audio component due to improper validation of
    user-supplied input when handling audio files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to play a specially crafted audio
    file, to execute arbitrary code. (CVE-2017-7015)

  - Multiple remote code execution vulnerabilities exist in
    the afclip component due to improper validation of
    user-supplied input when handling audio files. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities, by convincing a user to play a
    specially crafted audio file, to execute arbitrary
    code. (CVE-2017-7016, CVE-2017-7033)

  - A memory corruption issue exists in the
    AppleGraphicsPowerManagement component due to improper
    validation of input. A local attacker can exploit this
    to cause a denial of service condition or the execution
    of arbitrary code with system privileges.
    (CVE-2017-7021)

  - Multiple memory corruption issues exist in the kernel
    due to improper validation of input. A local attacker
    can exploit these issues to cause a denial of service
    condition or the execution of arbitrary code with system
    privileges. (CVE-2017-7022, CVE-2017-7024,
    CVE-2017-7026)

  - Multiple memory corruption issues exist in the kernel
    due to improper validation of input. A local attacker
    can exploit these issues to cause a denial of service
    condition or the execution of arbitrary code with kernel
    privileges. (CVE-2017-7023, CVE-2017-7025,
    CVE-2017-7027, CVE-2017-7069)

  - Multiple unspecified flaws exist in the kernel due to a
    failure to properly sanitize input. A local attacker can
    exploit these issues, via a specially crafted
    application, to disclose restricted memory contents.
    (CVE-2017-7028, CVE-2017-7029, CVE-2017-7067)

  - A flaw exists in the Foundation component due to
    improper validation of input. A unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    specially crafted file, to execute arbitrary code.
    (CVE-2017-7031)

  - A memory corruption issue exists in the 'kext tools'
    component due to improper validation of input. A local
    attacker can exploit this to execute arbitrary code with
    elevated privileges. (CVE-2017-7032)

  - Multiple unspecified flaws exist in the Intel Graphics
    Driver component due to a failure to properly sanitize
    input. A local attacker can exploit these issues, via a
    specially crafted application, to disclose restricted
    memory contents. (CVE-2017-7036, CVE-2017-7045)

  - A memory corruption issue exists in the libxpc component
    due to improper validation of input. A local attacker
    can exploit this issue, via a specifically crafted
    application, to cause a denial of service condition or
    the execution of arbitrary code with system privileges.
    (CVE-2017-7047)

  - Multiple memory corruption issues exist in the
    Bluetooth component due to improper validation of input.
    A local attacker can exploit these issues to execute
    arbitrary code with system privileges. (CVE-2017-7050,
    CVE-2017-7051)

  - A memory corruption issue exists in the Bluetooth
    component due to improper validation of input. A local
    attacker can exploit these issues to execute arbitrary
    code with system privileges. (CVE-2017-7054)

  - A buffer overflow condition exists in the Contacts
    component due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-7062)

  - A buffer overflow condition exists in the libarchive
    component due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, via a specially crafted archive file, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2017-7068)

  - A certificate validation bypass vulnerability exists in
    the curl component due to the program attempting to
    resume TLS sessions even if the client certificate
    fails. An unauthenticated, remote attacker can exploit
    this to bypass validation mechanisms. (CVE-2017-7468)

  - A memory corruption issue exists in the Broadcom BCM43xx
    family Wi-Fi Chips component that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2017-9417)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207922");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2017/May/47");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2017-003 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7069");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:"-");
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.(10\.5|11\.6|12\.5)([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.10.5 or Mac OS X 10.11.6 or Mac OS X 10.12.5");

if ("10.10.5" >< os || "10.11.6" >< os || "10.12.5" >< os) patch = "2017-003";

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = pgrep(
  pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd).*bom$",
  string:packages
);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  match = eregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(match[1]) || empty_or_null(match[2]))
    continue;

  patch_found = check_patch(year:int(match[1]), number:int(match[2]));
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
