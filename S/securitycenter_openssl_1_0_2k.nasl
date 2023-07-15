#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101046);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2016-7055", "CVE-2017-3731", "CVE-2017-3732");
  script_bugtraq_id(94242, 95813, 95814);

  script_name(english:"Tenable SecurityCenter OpenSSL 1.0.2 < 1.0.2k Multiple Vulnerabilities (TNS-2017-04)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains an
OpenSSL library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of OpenSSL :

  - A carry propagation error exists in the
    Broadwell-specific Montgomery multiplication procedure
    when handling input lengths divisible by but longer than
    256 bits. This can result in transient authentication
    and key negotiation failures or reproducible erroneous
    outcomes of public-key operations with specially crafted
    input. A man-in-the-middle attacker can possibly exploit
    this issue to compromise ECDH key negotiations that
    utilize Brainpool P-512 curves. (CVE-2016-7055)

  - An out-of-bounds read error exists when handling packets
    using the CHACHA20/POLY1305 or RC4-MD5 ciphers. An
    unauthenticated, remote attacker can exploit this, via
    specially crafted truncated packets, to cause a denial
    of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the x86_64
    Montgomery squaring implementation that may cause the
    BN_mod_exp() function to produce incorrect results. An
    unauthenticated, remote attacker with sufficient
    resources can exploit this to obtain sensitive
    information regarding private keys. Note that this issue
    is very similar to CVE-2015-3193. Moreover, the attacker
    would additionally need online access to an unpatched
    system using the target private key in a scenario with
    persistent DH parameters and a private key that is
    shared between multiple clients. For example, this can
    occur by default in OpenSSL DHE based SSL/TLS cipher
    suites. (CVE-2017-3732)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-04");
  script_set_attribute(attribute:"see_also", value:"https://static.tenable.com/prod_docs/upgrade_security_center.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170126.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.4.3 or later.
Alternatively, contact the vendor for a patch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3732");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/SecurityCenter/support/openssl/version");

  exit(0);
}

include("openssl_version.inc");
include("install_func.inc");

app = "OpenSSL (within SecurityCenter)";
fix = "1.0.2k";

sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (empty_or_null(sc_ver)) audit(AUDIT_NOT_INST, "SecurityCenter");

version = get_kb_item("Host/SecurityCenter/support/openssl/version");
if (empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, app);

if (
  openssl_ver_cmp(ver:version, fix:"1.0.2", same_branch:TRUE, is_min_check:FALSE) >= 0 &&
  openssl_ver_cmp(ver:version, fix:fix, same_branch:TRUE, is_min_check:FALSE) < 0
)
{
  report =
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
