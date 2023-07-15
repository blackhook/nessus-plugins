#TRUSTED 40aaade42f4b8ab9128452688ad7ca80b466ccf342bc247846144cf1696e370732feeafa0662862d7f3c89c786f539144d9a2927b88ba061ac73b0c9847d948322c502e8bf42377d3b3b809409424ac43530af6b968e5b082f47dc6960e7a0e4361eb8479b050486a436b2deb2082fcb3a7d0180b3520e581ef952d89f179f5ae7b4ae62c9b68c6d0af43ed2c5cd9fc452e3cec5efe372b677eba600ca952137c38e3997af124dd031b5bf00a1223bd1473293eb9262f9de3e43ba4e0603d936da39c9eae15339059a4b95b8ac00adeb591c95e76bc547168640a7916828eba1f4d5ec290a193747ab77d6726c3548068d0431bd6aab8c532f142c1d4de348263d88686878fc86cfddc09035d76d810bf7770fa19bcc2cbc7ad40dae410aba0c09a5a52a4f38bf569cfb349be39415086cad7e1e8f8c71168d37104eb3d60a049b47241ea2fc1746961246bf9e8e0f70ff42479455706625153639cafc87155019fcfb7b27c90669311a0209d4d20a82b632f31df7a0521fdf3bcf1a6853b8c16ff5c6a27a8309501c570862c2b33e0b5a4d1be5e1b297841e1f9e3b15ab20d1d7b6267baeb0ae0bb39bba06694fe73eb21fb231164d961ace041441c41f07cc4fff640171d88b2d75758edfd24917dd84140cf21098623fcd21341d5f7e24ce06b4045e4dfb47d3deca0cdb2d6b08285fefb9d1e9449ea16547f8702842c956
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31604);
 script_version("1.25");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

 script_cve_id(
  "CVE-2008-1002",
  "CVE-2008-1003",
  "CVE-2008-1004",
  "CVE-2008-1005",
  "CVE-2008-1006",
  "CVE-2008-1007",
  "CVE-2008-1008",
  "CVE-2008-1009",
  "CVE-2008-1010",
  "CVE-2008-1011"
 );
 script_bugtraq_id(
  28326,
  28328,
  28330,
  28332,
  28335,
  28336,
  28337,
  28338,
  28342,
  28347,
  28356
 );

 script_name(english:"Mac OS X : Apple Safari < 3.1");
 script_summary(english:"Check the Safari SourceVersion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues.");
 script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is older
than version 3.1.

The remote version of this software contains several security
vulnerabilities that may allow an attacker to execute arbitrary code
or launch a cross-site scripting attack on the remote host.

To exploit these flaws, an attacker would need to lure a victim into
visiting a rogue website or opening a malicious HTML file.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307563");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 3.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1010");

 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("macosx_apple_safari_installed.nbin");
 script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/uname", "MacOSX/Safari/Installed", "MacOSX/Safari/Path", "MacOSX/Safari/Version");
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X or macOS");

# Mac OS X 10.4, 10.5.2
uname = get_kb_item_or_exit("Host/uname");
if (!preg(pattern:"Darwin.* (8\.|9\.[012]\.)", string:uname))
  audit(AUDIT_HOST_NOT, "Mac OS X 10.4.x / 10.5 / 10.5.1 / 10.5.2");

get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path    = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

# And now the actual check.
fixed_version = "3.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
