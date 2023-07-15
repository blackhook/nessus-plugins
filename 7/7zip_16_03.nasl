#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109799);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:26");

  script_cve_id("CVE-2016-9296");
  script_bugtraq_id(94294);

  script_name(english:"7-Zip < 16.03 NULL Pointer Dereference DoS");
  script_summary(english:"Checks the version of 7-Zip.");

  script_set_attribute(attribute:"synopsis", value:
"A compression utility installed on the remote Windows host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of 7-Zip installed on the remote Windows host is prior to
16.03. It is, therefore, affected by a denial of service (DoS) flaw
due to a Null pointer dereference flaw.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/yangke/7zip-null-pointer-dereference");
  script_set_attribute(attribute:"see_also", value:"https://www.7-zip.org/history.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 7-Zip version 16.03 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("7zip_installed.nbin");
  script_require_keys("installed_sw/7-Zip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = '7-Zip';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

fix = "16.03";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version);
