#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135679);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id("CVE-2018-18311", "CVE-2019-1543", "CVE-2020-2961");
  script_bugtraq_id(106145, 107349, 108023);
  script_xref(name:"IAVA", value:"2020-A-0150-S");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the April 2020 CPU advisory.

  - Perl before 5.26.3 and 5.28.x before 5.28.1 has a buffer
    overflow via a crafted regular expression that triggers
    invalid write operations. (CVE-2018-18311)

  - ChaCha20-Poly1305 is an AEAD cipher, and requires a
    unique nonce input for every encryption operation. RFC
    7539 specifies that the nonce value (IV) should be 96
    bits (12 bytes). OpenSSL allows a variable nonce length
    and front pads the nonce with 0 bytes if it is less than
    12 bytes. However it also incorrectly allows a nonce to
    be set of up to 16 bytes. In this case only the last 12
    bytes are significant and any additional leading bytes
    are ignored. It is a requirement of using this cipher
    that nonce values are unique. Messages encrypted using a
    reused nonce value are susceptible to serious
    confidentiality and integrity attacks. If an application
    changes the default nonce length to be longer than 12
    bytes and then makes a change to the leading bytes of
    the nonce expecting the new value to be a new unique
    nonce then such an application could inadvertently
    encrypt messages with a reused nonce. Additionally the
    ignored bytes in a long nonce are not covered by the
    integrity guarantee of this cipher. Any application that
    relies on the integrity of these ignored leading bytes
    of a long nonce may be further affected. Any OpenSSL
    internal use of this cipher, including in SSL/TLS, is
    safe because no such use sets such a long nonce value.
    However user applications that use this cipher directly
    and set a non-default nonce length to be longer than 12
    bytes may be vulnerable. OpenSSL versions 1.1.1 and
    1.1.0 are affected by this issue. Due to the limited
    scope of affected deployments this has been assessed as
    low severity and therefore we are not creating new
    releases at this time. Fixed in OpenSSL 1.1.1c (Affected
    1.1.1-1.1.1b). Fixed in OpenSSL 1.1.0k (Affected
    1.1.0-1.1.0j). (CVE-2019-1543)

  - Vulnerability in the Enterprise Manager Base Platform product
  of Oracle Enterprise Manager (component: Discovery Framework
  (Oracle OHS)). Supported versions that are affected are 13.2.0.0
  and 13.3.0.0. Easily exploitable vulnerability allows unauthenticated
  attacker with network access via HTTP to compromise Enterprise Manager
  Base Platform. Successful attacks of this vulnerability can result
  in takeover of Enterprise Manager Base Platform. (CVE-2020-2961)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020
Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('oracle_rdbms_cpu_func.inc');
include('install_func.inc');

product = 'Oracle Enterprise Manager Cloud Control';
install = get_single_install(app_name:product, exit_if_unknown_ver:TRUE);
version = install['version'];
emchome = install['path'];

patchid = NULL;
missing = NULL;
patched = FALSE;
fix = NULL;

# TODO are we missing additional checks here?

if (version =~ '^13\\.3\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '31035765';
  fix = '13.3.0.0.200414';
}
else if (version =~ '^13\\.2\\.0\\.0(\\.[0-9]+)?$')
{
  patchid = '30990499';
  fix = '13.2.0.0.200414';
}
else if (version =~ '^12\\.1\\.0\\.5(\\.[0-9]+)?$')
{
  patchid = '31035728';
  fix = '12.1.0.5.200414';
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

order = make_list('Product', 'Version', 'Missing patch');
report = make_array(
  order[0], product,
  order[1], version,
  order[2], patchid
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
