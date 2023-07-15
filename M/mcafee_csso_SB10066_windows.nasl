#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73187);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2014-2536");
  script_bugtraq_id(66181);
  script_xref(name:"MCAFEE-SB", value:"SB10066");

  script_name(english:"McAfee Cloud Single Sign On < 4.0.1 Information Disclosure (SB10066) (Windows)");
  script_summary(english:"Checks version of MCSSO collected via SMB");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of McAfee Cloud Single Sign On (MCSSO) prior to 4.0.1 is
installed on the remote host. It is, therefore, affected by an
information disclosure vulnerability due to a failure to sanitize
user-supplied input, resulting in potential directory traversal. An
attacker could potentially exploit this vulnerability to download
arbitrary files, including one containing a hash of the product
administrator's password.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-14-050/");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10066");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 4.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:cloud_single_sign_on");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_csso_installed.nbin");
  script_require_keys("SMB/mcafee_csso/Path", "SMB/mcafee_csso/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/mcafee_csso/Path");
version = get_kb_item_or_exit("SMB/mcafee_csso/Version");

app_name = "McAfee Cloud Single Sign On";

fix = "4.0.1.197";
if (version =~ "^4\.0\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
