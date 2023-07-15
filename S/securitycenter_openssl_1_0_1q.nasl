#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88809);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2015-3194");
  script_bugtraq_id(78623);

  script_name(english:"Tenable SecurityCenter OpenSSL ASN.1 Signature Verification Routine DoS (TNS-2016-01)");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The SecurityCenter application installed on the remote host is
affected by a denial of service vulnerability in the bundled OpenSSL
library. The library is version 1.0.1 or later but prior to 1.0.1q. 
It is, therefore, affected by a NULL pointer dereference flaw in file
rsa_ameth.c due to improper handling of ASN.1 signatures that are
missing the PSS parameter. A remote attacker can exploit this to cause
the signature verification routine to crash, resulting in a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2016-01");
  script_set_attribute(attribute:"see_also", value:"https://static.tenable.com/prod_docs/upgrade_security_center.html");
  script_set_attribute(attribute:"see_also", value:"https://support.tenable.com/support-center/index.php?x=&mod_id=160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20151203.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.2.0. Alternatively, apply
the relevant patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3194");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/local_checks_enabled", "Host/SecurityCenter/support/openssl/version");

  exit(0);
}

include("openssl_version.inc");
include("misc_func.inc");
include("telnet_func.inc");
include("install_func.inc");


if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (! preg(pattern:"^(4\.6\.2\.2|4\.[7-8]\.[1-2]|5\.[0-1]\.[0-2](\.[0-1]|))$", string:sc_ver)) audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

fixes   = make_list("1.0.1q", "1.0.2e");
cutoffs = make_list("1.0.1", "1.0.2");
version = get_kb_item_or_exit("Host/SecurityCenter/support/openssl/version");

fix = NULL;

for ( i=0; i<2; i++)
{
  if (
    openssl_ver_cmp(ver:version, fix:fixes[i], same_branch:TRUE, is_min_check:FALSE) < 0 &&
    openssl_ver_cmp(ver:version, fix:cutoffs[i], same_branch:TRUE, is_min_check:FALSE) >= 0
  )
  {
    fix = fixes[i];
    break;
  }
}

if (!isnull(fix))
{
  report = '\n' +
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter OpenSSL version : ' + version +
    '\n  Fixed OpenSSL version          : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OpenSSL (within SecurityCenter)", version);
