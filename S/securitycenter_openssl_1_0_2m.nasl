#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104639);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2017-3735",
    "CVE-2017-3736"
  );
  script_bugtraq_id(
    100515,
    101666
  );

  script_name(english:"Tenable SecurityCenter OpenSSL 1.0.2 < 1.0.2m Multiple Vulnerabilities");
  script_summary(english:"Checks the version of OpenSSL in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains an
OpenSSL library that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of OpenSSL.");
  # https://docs.tenable.com/releasenotes/securitycenter/securitycenter76.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbaac4f6");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20170828.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20171102.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.6.0.1 or later.
Alternatively, apply SecurityCenter Patch SC-201711.1-5.x.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/16");

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
fix = "1.0.2m";

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
