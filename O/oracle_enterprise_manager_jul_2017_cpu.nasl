#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101837);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-7940",
    "CVE-2015-8607",
    "CVE-2015-8608",
    "CVE-2016-1181",
    "CVE-2016-2381",
    "CVE-2016-3092",
    "CVE-2016-5385",
    "CVE-2016-5386",
    "CVE-2016-5387",
    "CVE-2016-5388",
    "CVE-2017-3732",
    "CVE-2017-10091"
  );
  script_bugtraq_id(
    79091,
    80504,
    83802,
    86018,
    91068,
    91453,
    91815,
    91816,
    91818,
    91821,
    95814,
    99649
  );
  script_xref(name:"CERT", value:"797896");

  script_name(english:"Oracle Enterprise Manager Grid Control Multiple Vulnerabilities (July 2017 CPU) (httpoxy)");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise management application installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Enterprise Manager Grid Control installed on
the remote host is missing a security patch. It is, therefore,
affected by multiple vulnerabilities :

  - A flaw exists in the Bouncy Castle Java library due to
    improper validation of a point within the elliptic
    curve. An unauthenticated, remote attacker can exploit
    this to obtain private keys by using a series of
    specially crafted elliptic curve Diffie-Hellman (ECDH)
    key exchanges, also known as an 'invalid curve attack.'
    (CVE-2015-7940)

  - A flaw exists in the PathTools module for Perl in the
    File::Spec::canonpath() function that is triggered as
    strings are returned as untainted even when passing
    tainted input. An unauthenticated, remote attacker can
    exploit this to pass unvalidated user input to sensitive
    or insecure areas. (CVE-2015-8607)

  - An overflow condition exists in Perl in the MapPathA()
    function due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2015-8608)

  - A remote code execution vulnerability exists in the
    Apache Struts component due to improper handling of
    multithreaded access to an ActionForm instance. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted multipart request, to execute
    arbitrary code or cause a denial of service condition.
    (CVE-2016-1181)

  - A flaw exists in Perl that is triggered during the
    handling of variables that appear twice in the
    environment (envp), causing the last value to appear in
    %ENV, while getenv would return the first. An
    unauthenticated, remote attacker can exploit this to
    cause variables to be incorrectly propagated to
    subprocesses, regardless of the protections offered by
    taint checking. (CVE-2016-2381)

  - A denial of service vulnerability exists in the Apache
    Commons FileUpload component due to improper handling of
    boundaries in content-type headers when handling file
    upload requests. An unauthenticated, remote attacker can
    exploit this to cause processes linked against the
    library to become unresponsive. (CVE-2016-3092)

  - A man-in-the-middle vulnerability exists in various
    components, known as 'httpoxy', due to a failure to
    properly resolve namespace conflicts in accordance with
    RFC 3875 section 4.1.18. The HTTP_PROXY environment
    variable is set based on untrusted user data in the
    'Proxy' header of HTTP requests. The HTTP_PROXY
    environment variable is used by some web client
    libraries to specify a remote proxy server. An
    unauthenticated, remote attacker can exploit this, via a
    crafted 'Proxy' header in an HTTP request, to redirect
    an application's internal HTTP traffic to an arbitrary
    proxy server where it may be observed or manipulated.
    (CVE-2016-5385, CVE-2016-5386, CVE-2016-5387,
    CVE-2016-5388)

  - A carry propagating error exists in the OpenSSL
    component in the x86_64 Montgomery squaring
    implementation that may cause the BN_mod_exp() function
    to produce incorrect results. An unauthenticated, remote
    attacker with sufficient resources can exploit this to
    obtain sensitive information regarding private keys.
    Moreover, the attacker would additionally need online
    access to an unpatched system using the target private
    key in a scenario with persistent DH parameters and a
    private key that is shared between multiple clients. For
    example, this can occur by default in OpenSSL DHE based
    SSL/TLS cipher suites. (CVE-2017-3732)

  - An unspecified flaw exists in the UI Framework component
   that allows authenticated, remote attacker to have an
   impact on integrity. (CVE-2017-10091)");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76f5def7");
  script_set_attribute(attribute:"see_also", value:"https://support.oracle.com/rs?type=doc&id=2261562.1");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2017 Oracle Critical
Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("oracle_rdbms_cpu_func.inc");
include("install_func.inc");

product = "Oracle Enterprise Manager Cloud Control";
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patchid = NULL;
missing = NULL;
patched = FALSE;
fix = NULL;

if (version =~ "^13\.2\.0\.0(\.[0-9]+)?$")
{
  patchid = "25731746";
  fix = "13.2.0.0.170718";
}
else if (version =~ "^13\.1\.0\.0(\.[0-9]+)?$")
{
  patchid = "25904755";
  fix = "13.1.0.0.170718";
}
else if (version =~ "^12\.1\.0\.5(\.[0-9]+)?$")
{
  patchid = "25904769";
  fix = "12.1.0.5.170718";
}

if (isnull(patchid))
  audit(AUDIT_HOST_NOT, 'affected');

# compare version to check if we've already adjusted for patch level during detection
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, product, version, emchome);

# Now look for the affected components
patchesinstalled = find_patches_in_ohomes(ohomes:make_list(emchome));
if (isnull(patchesinstalled))
  missing = patchid;
else
{
  foreach applied (keys(patchesinstalled[emchome]))
  {
    if (applied == patchid)
    {
      patched = TRUE;
      break;
    }
    else
    {
      foreach bugid (patchesinstalled[emchome][applied]['bugs'])
      {
        if (bugid == patchid)
        {
          patched = TRUE;
          break;
        }
      }
      if (patched) break;
    }
  }
  if (!patched)
    missing = patchid;
}

if (empty_or_null(missing))
  audit(AUDIT_HOST_NOT, 'affected');

order = make_list('Product', 'Version', "Missing patch");
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
