#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109725);
  script_version("1.7");
  script_cvs_date("Date: 2018/07/16 12:48:31");

  script_cve_id(
    "CVE-2017-5754",
    "CVE-2018-8897",
    "CVE-2018-10982"
  );

  script_bugtraq_id(
    102378,
    104071
  );

  script_xref(name:"IAVA", value:"2018-A-0019");


  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX234679)");
  script_summary(english:"Checks for patches.");

  script_set_attribute(attribute:"synopsis", value:
"A server virtualization platform installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenServer running on the remote host is missing
a security hotfix. It is, therefore, affected by multiple
vulnerabilities."
);
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX234679");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2018/05/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:citrix:xenserver");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
pending = "Refer to vendor for patch/mitigation options";

if (version == "6.0.2")
{
  fix = "XS602ECC052"; # CTX234433
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2")
{
  fix = "XS62ESP1068"; # CTX234434
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.5($|[^0-9])")
{
  fix = "XS65ESP1066"; # CTX234435
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.0($|[^0-9])")
{
  fix = "XS70E055"; # CTX234436
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.1($|[^0-9])")
{
  fix = "XS71ECU1016"; # CTX234437
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.2($|[^0-9])")
{
  fix = "XS72E017"; # CTX234438
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.3($|[^0-9])")
{
  fix = "XS73E004"; # CTX234439
  if (fix >!< patches) vuln = TRUE;
}
else if (version =~ "^7\.4($|[^0-9])")
{
  fix = "XS74E001"; # CTX234440
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
