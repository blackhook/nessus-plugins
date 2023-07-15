#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104273);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2016-9269",
    "CVE-2016-9314",
    "CVE-2016-9315",
    "CVE-2016-9316"
  );
  script_xref(name:"EDB-ID", value:"41361");

  script_name(english:"Trend Micro IWSVA 6.5 < 6.5 Build 1737 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Trend Micro IWSVA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro InterScan Web Security Virtual Appliance
(IWSVA) installed on the remote host is 6.5 prior to 6.5 Build 1737.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to insecure
    access controls in the ManagePatches Servlet when uploading
    patches. This may allow an authenticated, remote attacker to
    upload a specially crafted patch and execute arbitrary commands.
    (CVE-2016-9269)

  - Insufficient access controls in ConfigBackup when downloading a
    backup of configuration files allows an authenticated, remote
    attacker to backup, disclose, or potentially manipulate certain
    files. (CVE-2016-9314)

  - Insufficient access controls in the updateaccountadministration
    servlet allows an authenticated, remote attacker to change
    administrator passwords or add administrative users.
    (CVE-2016-9315)

  - An insufficient input validation flaw exists in the handling of
    the 'accountnamelocal' and 'description' parameters to the
    updateaccountadministration servlet. Therefore, an authenticated,
    remote attacker can create a specially crafted request that will
    execute arbitrary script code in a user's browser session within
    the trust relationship between their browser and the server.
    (CVE-2016-9316)");
  script_set_attribute(attribute:"see_also", value:"https://success.trendmicro.com/solution/1116672");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2017/Feb/37");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2017/Feb/38");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro IWSVA version 6.5 Build 1737 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9269");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:interscan_web_security_virtual_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_iwsva_version.nbin");
  script_require_keys("Host/TrendMicro/IWSVA/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version  = get_kb_item_or_exit("Host/TrendMicro/IWSVA/version");
build    = get_kb_item("Host/TrendMicro/IWSVA/build");

name = "Trend Micro InterScan Web Security Virtual Appliance";

if (empty_or_null(build))
{
  if (report_paranoia > 0) build = "Unknown";
  else exit(0, "The build number of " + name + " could not be determined.");
}

# Only 6.5 is affected
if (version =~ "^6\.5($|[^0-9])")
{
  fix_ver = '6.5';
  fix_build = 1737;
}
else audit(AUDIT_INST_VER_NOT_VULN, name, version, build);

if (build == "Unknown" || build < fix_build)
{
  port = 0;

  order = make_list("Installed version", "Fixed version");
  report = make_array(
    order[0], version + ' Build ' + build,
    order[1], fix_ver + ' Build ' + fix_build
  );

  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, name, version, build);
