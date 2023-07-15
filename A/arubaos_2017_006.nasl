#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104176);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-9000", "CVE-2017-9003");

  script_name(english:"ArubaOS Multiple Vulnerabilities (2017-006)");
  script_summary(english:"Checks the ArubaOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of ArubaOS is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of ArubaOS installed on the remote host is affected by
multiple vulnerabilities, including SQL Injection, remote code
execution, arbitrary file access, and multiple memory corruption
flaws.");
  script_set_attribute(attribute:"see_also", value:"https://www.arubanetworks.com/assets/alert/ARUBA-PSA-2017-006.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Aruba PS version 6.3.1.25 / 6.4.4.16 / 6.5.1.9 / 6.5.3.3 / 6.5.4.2 / 8.1.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9000");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arubanetworks:arubaos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arubaos_detect.nbin");
  script_require_keys("Host/ArubaNetworks/model", "Host/ArubaNetworks/ArubaOS/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

model = get_kb_item_or_exit("Host/ArubaNetworks/model");
display_version = get_kb_item_or_exit("Host/ArubaNetworks/ArubaOS/version");

if(report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, "ArubaOS", display_version);

# Version may contain -FIPS at the end, unable to verify
version = ereg_replace(pattern:"-FIPS", replace:"", string:display_version);
fix = NULL;

if ( version =~ "^8\." ) fix = "8.1.0.4";
else if ( version =~ "^6\.5\.4" ) fix = "6.5.4.2";
else if ( version =~ "^6\.5\.[23]" ) fix = "6.5.3.3";
else if ( version =~ "^6\.5\.[01]" ) fix = "6.5.1.9";
else if ( version =~ "^6\.4" ) fix = "6.4.4.16";
else if (version =~ "^([0-5]\.[0-9])|^6\.[0-3]" ) fix = "6.3.1.25";
else audit(AUDIT_DEVICE_NOT_VULN, "ArubaOS", display_version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if ("FIPS" >< display_version) fix += "-FIPS";
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report, sqli:TRUE);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The ArubaOS device", display_version);
