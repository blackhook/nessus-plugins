#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76771);
  script_version("1.8");
  script_cvs_date("Date: 2018/07/09 12:26:58");

  script_cve_id("CVE-2014-4021", "CVE-2014-4947", "CVE-2014-4948");
  script_bugtraq_id(68070, 68659, 68660);

  script_name(english:"Citrix XenServer Multiple Vulnerabilities (CTX140984)");
  script_summary(english:"Checks XenServer version and installed hotfixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Citrix XenServer that is
affected by multiple vulnerabilities :

  - An information disclosure exists due to the Xen
    hypervisor's failure to properly clean memory pages.
    (CVE-2014-4021)

  - An unspecified vulnerability exists due to a buffer
    overflow in the HVM graphics console. (CVE-2014-4947)

  - XenServer is affected by an unspecified denial of
    service and information disclosure vulnerability.
    (CVE-2014-4948)");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX140984");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

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

# We will do our checks within the branches because 6.0.2 needs
# special treatment.
if (version == "6.0.0")
{
  fix = "XS60E039 / XS60E038";
  if ("XS60E039" >!< patches || "XS60E038" >!< patches) vuln = TRUE;
}
else if (version == "6.0.2")
{
  fix =  "XS602E035 or XS602ECC011 / XS602ECC010";
  if ("XS602E035" >!< patches && ("XS602ECC011" >!< patches || "XS602ECC010" >!< patches)) vuln = TRUE;
}
else if (version =~ "^6\.1\.")
{
  fix = "XS61E041 / XS61E040";
  if ("XS61E041" >!< patches || "XS61E040" >!< patches) vuln = TRUE;
}
else if (version =~ "^6\.2\.")
{
  fix = "XS62ESP1008";
  if ("XS62ESP1008" >!< patches) vuln = TRUE;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  port = 0;
  report =
    '\n  Installed version : ' + version +
    '\n  Missing hotfix    : ' + fix +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, extra:report, port:port);
}
else audit(AUDIT_PATCH_INSTALLED, fix);
