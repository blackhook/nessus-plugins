#TRUSTED 125f64d4a63c4573b5ef92f9a2e8a7f2e1f5ecf00d1bf9b5949408fb854a16751d3ee7529abf7d1d6a072da62a250494a2b0f7c315e7003f1128a6b1809b442faa075cfd8ca9eb9c8f0ea36d67498238a9b0d11c106cf82c5a8f1a4573e72d04281b6f81abbf445f92e90690ef5f5c0f8bf9c307132590de449271b14ab892428c55becde5ccc29ce21292d42c2e99bb014f7f86c27aaa90153a7991c8e72433eda9c3108169374acff6394c93ee3448fcc26d401c581e1096797f795873ca65e6f555503965ea4d031fcf08663682df87b4345a0d67816069ae99c8059b6b0efeedb2e1c44f544fd3d026b62405bbe74f267d31edd38ad2424018c4f31ffaba4f7bc0c8972657c3642594537f71e6a82dda63c1a16b445c3a8898e2b4756b9cf2bb01681f8c38b1c0449eb55b5b29509baaca6c50b73aa0b6f5e5594fbc00e09d127e3ebe04453a6d3eb65927bbecd6529b5de2f61d2052b5d799f09654add431d6add012819dd7cf617c4e257fd575eccceab3745dcea83185db425bd862a45c55651aa25f6af1894da954457b4ffbf6af00534508c55d6609dc935edce9f2237b4b356e6953b8690c71800856277581e5e968a508c83ecc5d4546f12d8c912d472edeb5ec536e83e77502ad1d720a7da2d01f078ca40d9c82946f5748fb75b2fcbd04c1f0eb7a2dccd12de9a14d05148dbde7003b7f0f3172f16c818f0d80
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77000);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0198",
    "CVE-2014-0224",
    "CVE-2014-3470"
  );
  script_bugtraq_id(66801, 67193, 67898, 67899);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"JSA", value:"JSA10629");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10629)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by the following vulnerabilities related to
OpenSSL :

  - An error exists in the ssl3_read_bytes() function
    that permits data to be injected into other sessions
    or allows denial of service attacks. Note that this
    issue is exploitable only if SSL_MODE_RELEASE_BUFFERS
    is enabled. (CVE-2010-5298)

  - An error exists in the do_ssl3_write() function that
    permits a NULL pointer to be dereferenced, which could
    allow denial of service attacks. Note that this issue
    is exploitable only if SSL_MODE_RELEASE_BUFFERS is
    enabled. (CVE-2014-0198)

  - An error exists in the processing of ChangeCipherSpec
    messages that allows the usage of weak keying material.
    This permits simplified man-in-the-middle attacks to be
    done. (CVE-2014-0224)

  - An error exists in the dtls1_get_message_fragment()
    function related to anonymous ECDH cipher suites. This
    could allow denial of service attacks. Note that this
    issue only affects OpenSSL TLS clients. (CVE-2014-3470)

Note that these issues only affects devices with J-Web or the SSL
service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10629");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10629.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");
include("global_settings.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# Versions 14 and later are not affected
ver_array = split(ver, sep:".", keep:FALSE);
ver_first = int(ver_array[0]);

if (ver_first > 14) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes    = make_array();
fix      = NULL;
fixed    = NULL;
nofix    = NULL;

if (ver =~ "^11\.4[^0-9]")
{
  fixes['11.4'] = '11.4R12-S4';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2014-0198 (fixed in 11.4R12-S4)';

    fixes['11.4'] = '11.4R12-S1';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "11.4R12-S4 \ 11.4R12-S1";
      fixed += '\n    CVE-2014-0076, CVE-2014-0224 (fixed in 11.4R12-S1)';
    }
    else
      fix = "11.4R12-S4";
  }
  nofix = "CVE-2010-5298";
}

else if (ver =~ "^12\.1X44[^0-9]")
{
  fixes['12.1X44'] = '12.1X44-D40';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2010-5298, CVE-2014-0076, CVE-2014-0198, CVE-2014-0224";
}

else if (ver =~ "^12\.1X46[^0-9]")
{
  fixes['12.1X46'] = '12.1X46-D20';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2010-5298, CVE-2014-0076, CVE-2014-0198, CVE-2014-0224";
}

else if (ver =~ "^12\.1X47[^0-9]")
{
  fixes['12.1X47'] = '12.1X47-D15';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2014-0198, CVE-2014-0224 (fixed in 12.1X47-D15)';
    fixes['12.1X47'] = '12.1X47-D10';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = '12.1X47-D15 / 12.1X47-D10';
      fixed += '\n    CVE-2010-5298, CVE-2014-0076 (fixed in 12.1X47-D10)';
    }
    else
      fix = "12.1X47-D15";
  }
}

else if (ver =~ "^12\.2[^0-9]")
{
  fixes['12.2'] = '12.2R9';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2010-5298, CVE-2014-0076, CVE-2014-0198, CVE-2014-0224";
}

else if (ver =~ "^12\.3[^0-9]")
{
  fixes['12.3'] = '12.3R8';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2014-0198, CVE-2014-0224 (fixed in 12.3R8)';

    fixes['12.3'] = '12.3R7';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "12.3R8 \ 12.3R7";
      fixed += '\n    CVE-2010-5298, CVE-2014-0076 (fixed in 12.3R7)';
    }
    else
      fix = "12.3R8";
  }
}

else if (ver =~ "^13\.1[^0-9]")
{
  fixes['13.1'] = '13.1R4-S3';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed = '\n    CVE-2010-5298, CVE-2014-0076, CVE-2014-0198 (fixed in 13.1R4-S3)';
    fixes['13.1'] = '13.1R4-S2';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "13.1R4-S3 \ 13.1R4-S2";
      fixed += '\n    CVE-2014-0224 (fixed in 13.1R4-S2)';
    }
    else
      fix = "13.1R4-S3";
  }
}

else if (ver =~ "^13\.2[^0-9]")
{
  fixes['13.2'] = '13.2R5-S1';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    fixed += '\n    CVE-2014-0076, CVE-2014-0198 (fixed in 13.2R5-S1)';
    fixes['13.2'] = '13.2R5';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "13.2R5-S1 \ 13.2R5";
      fixed += '\n    CVE-2010-5298, CVE-2014-0224 (fixed in 13.2R5)';
    }
    else
      fix = "13.2R5-S1";
  }
}

else if (ver =~ "^13\.3[^0-9]")
{
  fixes['13.3'] = '13.3R3';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
  {
    # nb 13.3 is not affected by CVE-2014-0076
    fixed = '\n    CVE-2010-5298, CVE-2014-0198, CVE-2014-0224 (fixed in 13.3R3)';
    fixes['13.3'] = '13.3R2-S3';
    fix = check_junos(ver:ver, fixes:fixes);
    if (fix)
    {
      fix = "13.3R3 \ 13.3R2-S3";
      fixed += '\n    CVE-2010-5298, CVE-2014-0224 (fixed in 13.3R2-S3)';
    }
    else
      fix   = '13.3R3';
  }
}

else if (ver =~ "^14\.1[^0-9]")
{
  fixes['14.1'] = '14.1R2';
  fix = check_junos(ver:ver, fixes:fixes);
  if (fix)
    fixed = "CVE-2014-0198";
}

# Check if host is affected
if (isnull(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

# HTTPS or XNM-SSL must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set system services web-management https interface", # HTTPS
    "^set system services xnm-ssl" # SSL Service for JUNOScript (XNM-SSL)
  );
  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }
  if (override) audit(AUDIT_HOST_NOT,
    'affected because J-Web and SSL Service for JUNOScript (XNM-SSL) are not enabled');
}

# Report
if (report_verbosity > 0)
{
  report =
    '\n  Installed version    : ' + ver +
    '\n  Fixed version        : ' + fix;

  if (!isnull(fixed))
    report += '\n  CVEs fixed           : ' + fixed;

  if (!isnull(nofix))
    report += '\n  No fix available for : ' + nofix;

  report += '\n';

  security_warning(port:0, extra:report + junos_caveat(override));
}
else security_warning(port:0, extra:junos_caveat(override));
