#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102526);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id(
    "CVE-2017-12134",
    "CVE-2017-12135",
    "CVE-2017-12136",
    "CVE-2017-12137",
    "CVE-2017-12855"
  );
  script_bugtraq_id(
    100343,
    100344,
    100346,
    100341,
    100342
  );

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX225941)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities as noted in the CTX225941 advisory."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX225941");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12134");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/08/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/16");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
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

# two hotfixes for each series
if (version == "6.0.2")
{
  fix = "XS602ECC047"; # CTX226371
  if (fix >!< patches) vuln = TRUE;

}
else if (version =~ "^6\.2\.0")
{
  fix = "XS62ESP1063"; # CTX226372
  if (fix >!< patches) vuln = TRUE;

}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1059 and XS65ESP1060"; # CTX226373 and CTX226376
  if ("XS65ESP1059" >!< patches && "XS65ESP1060" >!< patches) vuln = TRUE;

}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E039 and XS70E040"; # CTX226374 and CTX226377
  if ("XS70E039" >!< patches && "XS70E040" >!< patches) vuln = TRUE;

}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71E013 and XS71E014"; # CTX226298 and CTX226299
  if ("XS71E013" >!< patches && "XS71E014" >!< patches && "XS71ECU" >!< patches) vuln = TRUE;

}
else if (version =~ "^7\.2($|[^0-9])")
{
  fix = "XS72E004 and XS72E005"; # CTX226375 and CTX226375
  if ("XS72E004" >!< patches && "XS72E005" >!< patches) vuln = TRUE;

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
