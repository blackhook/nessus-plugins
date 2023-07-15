#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105083);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/30");

  script_cve_id(
    "CVE-2017-7980",
    "CVE-2017-15592",
    "CVE-2017-17044",
    "CVE-2017-17045"
  );
  script_bugtraq_id(
    97955,
    101513,
    102008,
    102013
  );

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX230138)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer installed on the remote host is
missing a security hotfix. It is, therefore, affected by multiple
vulnerabilities as noted in the CTX230138 advisory.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX230138");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17045");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

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
  if ("XS72E010" >!< patches) # CTX229541
  {
    fix = "XS72E010";
    vuln = TRUE;
  }
  if ("XS72E012" >!< patches) # CTX230161
  {
    if (empty_or_null(fix))
      fix = "XS72E012";
    else
      fix += " and XS72E012";
    vuln = TRUE;
  }
}
else if (version =~ "^7\.1($|[^0-9])")
{
  # LTSR CU1 CTX229540 & CTX230160, LTSR CTX229545 & CTX230159
  # No patch applied
  if ("XS71ECU" >!< patches && "XS71E018" >!< patches && "XS71E019" >!< patches)
  {
    fix = "XS71ECU1006 and XS71ECU1008, or XS71E018 and XS71E019";
    vuln = TRUE;
  }
  # LTSR CU1 patch applied
  else if ("XS71ECU" >!< patches && ("XS71ECU1006" >< patches || "XS71ECU1008" >< patches))
  {
    if ("XS71ECU1006" >!< patches) # CTX229540
    {
      fix = "XS71ECU1006";
      vuln = TRUE;
    }
    else if ("XS71ECU1008" >!< patches) # CTX230160
    {
      fix = "XS71ECU1008";
      vuln = TRUE;
    }
  }
  # LTSR patch applied
  else if ("XS71E018" >< patches || "XS71E019" >< patches)
  {
    if ("XS71E018" >!< patches) # CTX229545
    {
      fix = "XS71E018";
      vuln = TRUE;
    }
    else if ("XS71E019" >!< patches) # CTX230159
    {
      fix = "XS71E019";
      vuln = TRUE;
    }
  }
}
else if (version =~ "^7\.0($|[^0-9])")
{
  if ("XS70E048" >!< patches) # CTX229539
  {
    fix = "XS70E048";
    vuln = TRUE;
  }
  if ("XS70E049" >!< patches) # CTX229544
  {
    if (empty_or_null(fix))
      fix = "XS70E049";
    else
      fix += " and XS70E049";
    vuln = TRUE;
  }
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1064"; # CTX229543
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2($|[^0-9])")
{
  fix = "XS62ESP1066"; # CTX229096
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.0\.2($|[^0-9])")
{
  fix = "XS602ECC050"; # CTX229095
  if (fix >!< patches) vuln = TRUE;
}

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
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
