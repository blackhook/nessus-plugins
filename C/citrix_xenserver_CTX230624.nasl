#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105370);
  script_version("1.6");
  script_cvs_date("Date: 2018/08/08 12:52:14");


  script_name(english:"Citrix XenServer Guest-to-host DoS (CTX230624)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by a
denial-of-service vulnerability as noted in the CTX230624 advisory.

Note this vulnerability only affects Citrix XenServer 7.2 and 7.1 LTSR
CU1.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX230624");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/12/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/19");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

if (version =~ "^7\.2($|[^0-9])")
{
  fix = "XS72E011"; # CTX230237
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71ECU1007"; # CTX230236, Patch only for 7.1 LTSR CU1
  if (fix >!< patches ) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Missing hotfix", fix
    ),
    ordered_fields:make_list("Installed version", "Missing hotfix")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
