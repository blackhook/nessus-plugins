#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105084);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_xref(name:"CERT", value:"577193");

  script_name(english:"Check Point Gaia Operating System SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (sk103683) (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by an SSL/TLS vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Gaia Operating System
that is potentially affected by a man-in-the-middle (MitM) information
disclosure vulnerability known as POODLE. The vulnerability is due to
the way SSL 3.0 handles padding bytes when decrypting messages
encrypted using block ciphers in cipher block chaining (CBC) mode.
MitM attackers can decrypt a selected byte of a cipher text in as few
as 256 tries if they are able to force a victim application to
repeatedly send the same data over newly created SSL 3.0 connections.

As long as a client and service both support SSLv3, a connection can
be 'rolled back' to SSLv3, even if TLSv1 or newer is supported by the
client and service.

The TLS Fallback SCSV mechanism prevents 'version rollback' attacks
without impacting legacy clients; however, it can only protect
connections when the client and service support the mechanism. Sites
that cannot disable SSLv3 immediately should enable this mechanism.

This is a vulnerability in the SSLv3 specification, not in any
particular SSL implementation. Disabling SSLv3 is the only way to
completely mitigate the vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk103683&src=securityAlerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab309e24");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor supplied patch, mitigations or contact the vendor
for further information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:T/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:check_point:gaia_os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("check_point_gaia_os_version.nbin");
  script_require_keys("Host/Check_Point/version", "Host/Check_Point/model", "Host/Check_Point/enabled_blades", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");
include("obj.inc");

app_name = "Gaia Operating System";
version  = get_kb_item_or_exit("Host/Check_Point/version");
model    = get_kb_item_or_exit("Host/Check_Point/model");
take     = get_kb_item("Host/Check_Point/jumbo_hf");
enabled_blades     = get_kb_item_or_exit("Host/Check_Point/enabled_blades");
installed_hotfixes = get_kb_item("Host/Check_Point/installed_hotfixes");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (empty_or_null(take))
  take = 0;
else
  take = int(take);

if (empty_or_null(installed_hotfixes))
  installed_hotfixes = "";


vuln = FALSE;

################
# Blades check
################
potentially_vuln_blades = make_list();
vuln_blades = make_list(
    "appi",            # Application Control
    "av",              # Anti-Virus
    "dlp",             # DLP (Data Loss Prevention)
    "ia",              # Identity Awareness alt. No. 1
    "identityServer",  # Identity Awareness alt. No. 1
    "ips",             # IPS (Intrusion Prevention System)
    #"??",             # Mobile Access
    "ted",             # Threat Emulation alt. No. 2
    "ThreatEmulation", # Threat Emulation alt. No. 1
    "urlf",            # URL Filtering
    #"??",             # User Check
    "vpn"              # VPN (Virtual Private Network)
);

foreach vuln_blade (vuln_blades)
{
  foreach enabled_blade (split(enabled_blades, keep:FALSE))
  {
    if (vuln_blade == enabled_blade)
      potentially_vuln_blades = make_list(potentially_vuln_blades, enabled_blade);
  }
}

if (!max_index(potentially_vuln_blades))
  audit(AUDIT_HOST_NOT, "a Gaia OS device containing the affected blades");

################
# Hotfix check
################
# Fixed by Hotfixes (or included in) :
# sk103683 - main
# sk105062 - super - Check Point response to TLS FREAK Attack (CVE-2015-0204)
if (
  "sk103683" >< installed_hotfixes ||
  "sk105062" >< installed_hotfixes
)
  audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");

################
# Ver check
################
# Fixed in :: Check Point R77.30
# ...
if (
  # Fixed in :: Check Point vSEC Gateway R77.20VSEC
  (version == "R77VSEC" || version =~ "^R77\.([0-9]|1[0-9])VSEC")
  ||
  # Fixed in :: Check Point R76SP.20 for 61000 / 41000
  (version =~ "^R76SP\.([0-9]|1[0-9])($|[^0-9])" && model =~ "^Check Point [46]1000$" && take == 0)
  ||
  # Fixed in :: Check Point R77.20 for 600 / 1100 / 1200R Appliance
  (version =~ "^R77\.([0-9]|1[0-9])($|[^0-9])" && model =~ "^Check Point (600|1100|1200R)$")
  ||
  # Fixed in :: Check Point R77.20.15 for 700 Appliance
  (version =~ "^R77\.([0-9]|1[0-9]|20\.([0-9]|1[0-4]))($|[^0-9])" && model =~ "^Check Point 700($|[^0-9])")
  ||
  # Fixed in :: Jumbo Hotfix Accumulator for R77.20 - since Take_50
  (version == "R77.20" && take != 0 && take < 50)
  ||
  # Fixed in :: Jumbo Hotfix Accumulator for R77.10 - since Take_88
  (version == "R77.10" && take != 0 && take < 88)
  ||
  # Fixed in :: Jumbo Hotfix Accumulator for R77 - since Take_37
  (version == "R77" && take != 0 && take < 37)
  ||
  # Fixed in :: Jumbo Hotfix Accumulator for R76 - since Take_50
  (version == "R76" && take != 0 && take < 50)
  ||
  # Fixed in :: Jumbo Hotfix Accumulator for R76SP.10 on 61000/41000 - since Take_37
  (version == "R76SP.10" && model =~ "^Check Point [46]1000$" && take != 0 && take < 37)
  ||
  # Fixed in :: Jumbo Hotfix Accumulator for R75.47 - since Take_67
  (version == "R75.47" && take != 0 && take < 67)
)
{
  report =
    '\n  Installed version      : ' + version +
    '\n  Affected blades        : ' + join(potentially_vuln_blades, sep:", ") +
    '\n  Hotfix required        : See Solution.' +
    '\n';
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The remote device running " + app_name + " (version " + version + ")");

