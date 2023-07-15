#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106199);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2017-3735", "CVE-2017-3736", "CVE-2017-5645");
  script_bugtraq_id(97702, 100515, 101666);

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (January 2018 CPU)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Secure Global Desktop installed on the remote
host is 5.3 and is missing a security patch from the January 2018
Critical Patch Update (CPU). It is, therefore, affected by multiple
vulnerabilities:

  - The included OpenSSL library has a off-by-one out-of-bounds read
    flaw within the X509v3_addr_get_afi() function of
    crypto/x509v3/v3_addr.c when handling the IPAddressFamily
    extension of X.509 certificates. A content-dependent attacker,
    with a specially crafted request, could potentially read limited
    memory information. (CVE-2017-3735)

  - The included OpenSSL library has a carry propagating flaw within
    the bn_sqrx8x_internal() function in crypto/bn/asm/x86_64-mont5.pl
    when handling RSA / DSA encryption. A content-dependent attacker,
    with a specially crafted request, could potentially determine the
    private key. (CVE-2017-3736)

  - The included Apache Log4j contains a flaw due to improper
    validation of log events before deserializing. A remote attacker,
    with a specially crafted log event, could potentially execute
    arbitrary script code. (CVE-2017-5645)");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html#AppendixOVIR
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e66274f");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2018 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Oracle Secure Global Desktop";
version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

fix_required = NULL;

if (version =~ "^5\.30($|\.)") fix_required = 'Patch_53p3';

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
{
  if (patch == fix_required)
  {
    patched = TRUE;
    break;
  }
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + fix_required + ')');

report = '\n  Installed version : ' + version +
         '\n  Patch required    : ' + fix_required +
         '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);

