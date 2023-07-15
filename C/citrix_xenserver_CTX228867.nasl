#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103927);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id(
    "CVE-2017-15588",
    "CVE-2017-15589",
    "CVE-2017-15590",
    "CVE-2017-15592",
    "CVE-2017-15593",
    "CVE-2017-15594",
    "CVE-2017-15595"
  );
  script_bugtraq_id(101490);

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX228867)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities as noted in the CTX228867 advisory.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX228867");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15595");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");

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
  fix = "XS72E008"; # CTX228722
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71E016 and XS71ECU1003"; # CTX228720 and CTX228721
  if ("XS71E016" >!< patches && "XS71ECU" >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E046"; # CTX228719
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1062"; # CTX228718
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1065"; # CTX228717
  if (fix >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix = "XS602ECC049"; # CTX228716
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
