#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104174);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id("CVE-2017-15597");
  script_bugtraq_id(101564);

  script_name(english:"Citrix XenServer Pin Count / Page Reference Grant Table Code Guest-to-Host Memory Corruption Vulnerability (CTX229057)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by a memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by a memory
corruption vulnerability as noted in the CTX229057 advisory.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX229057");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15597");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_xenserver_version.nbin");
  script_require_keys("Host/XenServer/version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix XenServer";
version = get_kb_item_or_exit("Host/XenServer/version");
get_kb_item_or_exit("Host/local_checks_enabled");
patches = get_kb_item("Host/XenServer/patches");
vuln = FALSE;
fix = '';

if (version =~ "^7\.2($|[^0-9])")
{
  fix = "XS72E009"; # CTX229067
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71E017 and XS71ECU1004"; # CTX229065 & CTX229066
  if ("XS71E017" >!< patches && "XS71ECU" >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E047"; # CTX229064
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1063"; # CTX229063
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
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
