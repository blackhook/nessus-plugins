#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104573);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-15525", "CVE-2017-15526");
  script_bugtraq_id(101697, 101698);

  script_name(english:"Symantec Endpoint Encryption < 11.1.3 MP1 (SYM17-012)");
  script_summary(english:"Checks the version of Symantec Endpoint Encryption Drive Encryption.");

  script_set_attribute(attribute:"synopsis", value:
"A drive encryption management agent installed on the remote Windows
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Symantec Endpoint Encryption (SEE) Drive 
Encryption Client installed on the remote Windows host is 
prior to 11.1.3 MP1. It is, therefore, affected by a denial 
of service and NULL pointer vulnerability.");
  # https://support.symantec.com/en_US/article.SYMSA1420.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c460f804");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Encryption version 11.1.3 MP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15526");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_encryption");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_encryption_drive_encryption_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Symantec Endpoint Encryption Drive Encryption Client");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Symantec Endpoint Encryption Drive Encryption Client";
fix = "11.1.3.810";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port))
    port = 445;

  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", "11.1.3.810"
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
