#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(101165);
  script_version ("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id("CVE-2017-5697");
  script_bugtraq_id(99064);
  script_xref(name:"IAVA", value:"2017-A-0186-S");

  script_name(english:"Intel Active Management Technology (AMT) Web UI Clickjacking Weakness (INTEL-SA-00081) (remote check)");
  script_summary(english:"Checks the version of Intel manageability firmware via server header.");

  script_set_attribute(attribute:"synopsis", value:
"The management engine on the remote host is affected by a clickjacking
weakness.");
  script_set_attribute(attribute:"description", value:
"The Intel Management Engine on the remote host has Active Management
Technology (AMT) enabled, and according to its self-reported version
in the banner, it is running Intel manageability firmware version
9.0.x or 9.1.x prior to 9.1.40.1000, 9.5.x prior to 9.5.60.1952,
10.0.x prior to 10.0.50.1004, 11.0.x prior to 11.0.0.1205, or 11.6.x
prior to 11.6.25.1129. It is, therefore, affected by a clickjacking
weakness in the web user interface due to a failure to conceal
hyperlinks beneath legitimate, clickable content using opaque
overlays. An unauthenticated, remote attacker can exploit this, via a
specially crafted web page, to make users perform unintended actions
or to hijack users' web clicks.");
  # https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00081&languageid=en-fr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c588d910");
  script_set_attribute(attribute:"see_also", value:"https://support.lenovo.com/us/en/product_security/LEN-14005");
  script_set_attribute(attribute:"solution", value:
"Contact your system OEM for updated firmware per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:intel:active_management_technology");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:intel:active_management_technology_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 16992, 16993, 16994, 16995, 623, 664);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

port = get_http_port(default:16992);

service = "Intel Active Management Technology";
banner = get_http_banner(port:port);

if (banner !~ "Server: (AMT|Intel\(R\) (Active Management Technology|Standard Manageability))")
  audit(AUDIT_NOT_LISTEN, service, port);
else banner = strstr(banner, "Server:"); # slice banner

# check for just AMT, which does not have any version info
if (banner =~ "^Server: AMT$") audit(AUDIT_UNKNOWN_WEB_SERVER_VER, service, port);

# otherwise get Intel Manageability firmware version
pat = "^Server: Intel\(R\) (?:Active Management Technology|Standard Manageability) ([0-9.]+)";
version = pregmatch(string:banner, pattern:pat);
if (isnull(version)) audit(AUDIT_NOT_LISTEN, service, port);
else version = version[1];

if (version =~ "^9\.[01]\.")
{
  fix = "9.1.40";
  fix_disp = "9.1.40.1000";
}
else if (version =~ "^9\.5\.")
{
  fix = "9.5.60";
  fix_disp = "9.5.60.1952";
}
else if (version =~ "^10\.0\.")
{
  fix = "10.0.50";
  fix_disp = "10.0.50.1004";
}
else if (version =~ "^11\.0\.")
{
  fix = "11.0.0";
  fix_disp = "11.0.0.1205";
}
else if (version =~ "^11\.6\.")
{
  fix = "11.6.25";
  fix_disp = "11.6.25.1129";
}
else
  audit(AUDIT_LISTEN_NOT_VULN, service, port, version);

# the one case we can't be sure it's vuln/patched
if (ver_compare(ver:version, fix:fix, strict:FALSE) == 0)
  audit(AUDIT_VER_NOT_GRANULAR, service, port, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  order = make_list('Intel Manageability Firmware', 'Fixed Firmware');
  report = make_array(
    order[0], version,
    order[1], fix_disp
  );

  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, service, port, version);
