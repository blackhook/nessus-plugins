#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108887);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/09 12:26:58");

  script_cve_id("CVE-2016-2074", "CVE-2018-7540", "CVE-2018-7541");
  script_bugtraq_id(85700, 103174, 103177);

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX232655)"); 
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple
vulnerabilities."
);
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX232655");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2018/03/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/06");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version =~ "^7\.0($|[^0-9])")
{
  fix1 = "XS70E052"; # CTX233362
  fix2 = "XS70E051"; # CTX233364
  if (fix1 >!< patches && fix2 >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71ECU1012"; # CTX233365
  fix2 = "XS71ECU1013"; # CTX233363
  if (fix >!< patches && fix2 >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.2($|[^0-9])")
{
  fix = "XS72E016"; # CTX233366
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.3($|[^0-9])")
{
  fix = "XS73E003"; # CTX233368
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
