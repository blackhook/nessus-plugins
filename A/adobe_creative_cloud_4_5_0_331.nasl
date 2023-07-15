#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109729);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-4873", "CVE-2018-4991", "CVE-2018-4992");
  script_bugtraq_id(104103);

  script_name(english:"Adobe Creative Cloud Desktop < 4.5.0.331 Multiple Vulnerabilities (APSB18-12)");
  script_summary(english:"Checks the version of Creative Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote
Windows host is prior to 4.5.0.331. It is, therefore, affected by the
multiple vulnerabilities as noted in the APSB18-12 advisory.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb18-12.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a867558d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 4.5.0.331 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4991");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("installed_sw/Adobe Creative Cloud");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Adobe Creative Cloud';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

# For Adobe products, we compare the highest affected product, rather
# than the "fixed" version, as there is an ambiguous gap between what
# is considered affected and the fix.
highest_affected = "4.4.1.298";
fix = "4.5.0.331";

if (ver_compare(ver:version, fix:highest_affected, strict:FALSE) <= 0)
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

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
