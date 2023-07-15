#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90681);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-7182");
  script_bugtraq_id(77416);

  script_name(english:"Oracle GlassFish Server 2.1.1.x < 2.1.1.27 NSS ASN.1 Decoder RCE (April 2016 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle GlassFish Server
running on the remote host is 2.1.1.x prior to 2.1.1.27. It is,
therefore, affected by a heap buffer overflow condition in the ASN.1
decoder in the Network Security Services (NSS) library. A remote
attacker can exploit this, via crafted OCTET STRING data, to cause a
denial of service or to execute arbitrary code.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffb7b96f");
  # https://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56572c1f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 2.1.1.27 or later as
referenced in the April 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("glassfish.inc");

#
# Main
#

# Check for GlassFish
get_kb_item_or_exit('www/glassfish');

port = get_glassfish_port(default:8080);

# Get the version number out of the KB.
ver = get_kb_item_or_exit("www/" + port + "/glassfish/version");
banner = get_kb_item_or_exit("www/" + port + "/glassfish/source");
pristine = get_kb_item_or_exit("www/" + port + "/glassfish/version/pristine");

# Set appropriate fixed versions.
if (ver =~ "^2\.1\.1(\.|$)") fix = "2.1.1.27";
else fix = NULL;

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + pristine +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle GlassFish", port, pristine);
