#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102699);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2016-7055", "CVE-2017-3731", "CVE-2017-3732");
  script_bugtraq_id(94242, 95813, 95814);
  script_xref(name:"JSA", value:"JSA10775");

  script_name(english:"Juniper Junos Multiple OpenSSL Vulnerabilities (JSA10775)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple vulnerabilities :

  - A carry propagation error exists in the OpenSSL
    component in the Broadwell-specific Montgomery
    multiplication procedure when handling input lengths
    divisible by but longer than 256 bits. This can result
    in transient authentication and key negotiation failures
    or reproducible erroneous outcomes of public-key
    operations with specially crafted input. A
    man-in-the-middle attacker can possibly exploit this
    issue to compromise ECDH key negotiations that utilize
    Brainpool P-512 curves. (CVE-2016-7055)

  - An out-of-bounds read error exists in the OpenSSL
    component when handling packets using the
    CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the OpenSSL
    component in the x86_64 Montgomery squaring
    implementation that may cause the BN_mod_exp() function
    to produce incorrect results. An unauthenticated, remote
    attacker with sufficient resources can exploit this to
    obtain sensitive information regarding private keys.
    (CVE-2017-3732)

Note that these vulnerabilities only affect devices with J-Web or the
SSL service for JUNOScript enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10775");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170126.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10775. Alternatively, disable the J-Web service
and use Netconf for JUNOScript rather than SSL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
if (ver =~ "^14\.1R8")          fixes['14.1R'] = '14.1R8-S3';
else                            fixes['14.1R'] = '14.1R9';
fixes['14.1X53'] = '14.1X53-D43'; # or 14.1X53-D50
if (ver =~ "^14\.2R4")          fixes['14.2R'] = '14.2R4-S7';
else if (ver =~ "^14\.2R7")     fixes['14.2R'] = '14.2R7-S6';
else                            fixes['14.2R'] = '14.2R8';
if ( ver =~ "^15\.1F5")         fixes['15.1F'] = '15.1F5-S7';
else if ( ver =~ "^15\.1F6")  fixes['15.1F'] = '15.1F6-S6';
if (ver =~ "^15\.1R5")          fixes['15.1R'] = '15.1R5-S2';
else                            fixes['15.1R'] = '15.1R6';
fixes['15.1X49'] = '15.1X49-D100';
fixes['15.1X53'] = '15.1X53-D46'; # or D57, D63, D70, 230
fixes['15.1X56'] = '15.1X56-D62';
if (ver =~ "^16\.1R3")          fixes['16.1R'] = '16.1R3-S3';
else if (ver =~ "^16\.1R4")     fixes['16.1R'] = '16.1R4-S1';
else                            fixes['16.1R'] = '16.1R5';
if (ver =~ "^16\.2R1")          fixes['16.2R'] = '16.2R1-S3';
else                            fixes['16.2'] = '16.2R2';
fixes['17.1'] = '17.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
