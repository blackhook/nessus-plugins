#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110779);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3665");
  script_bugtraq_id(104460);

  script_name(english:"Citrix XenServer Information Disclosure Vulnerability (CTX235225)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX235745");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
pending = "Refer to vendor for patch/mitigation options";

if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E058"; # CTX235958
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71ECU1022"; # CTX235957
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.3($|[^0-9])")
{
  fix = "XS73E006"; # CTX235956
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.4($|[^0-9])")
{
  fix = "XS74E003"; # CTX235175
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.5($|[^0-9])")
{
  fix = "XS75E001"; # CTX235135
  if (fix >!< patches) vuln = TRUE;
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
