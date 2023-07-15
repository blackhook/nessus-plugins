#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100682);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-6087");
  script_bugtraq_id(98794);
  script_xref(name:"IAVB", value:"2017-B-0064");

  script_name(english:"IBM Domino 8.5.x / 9.0.x < 9.0.1 Fix Pack 8 TLS Server Diffie-Hellman Key Validation MitM");

  script_set_attribute(attribute:"synopsis", value:
"A business collaboration application running on the remote host is
affected by a key validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM Domino (formerly IBM
Lotus Domino) running on the remote host is 8.5.x or 9.0.x prior to
9.0.1 Fix Pack 8. It is, therefore, affected by a flaw in the TLS
server due to improper validation of Diffie-Hellman parameters. A
man-in-the-middle (MitM) attacker can exploit this, via a small
subgroup attack, to more easily break the encryption and thereby
compromise the connection between the server and clients, resulting in
the disclosure of user authentication credentials.");
  # https://www.ibm.com/blogs/psirt/ibm-security-bulletin-ibm-domino-tls-server-diffie-hellman-key-validation-vulnerability-cve-2016-6087/*
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cdf263c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 9.0.1 Fix Pack 8 or later.

Note that users who remain on the following releases may open a
service request with IBM Support for a custom hotfix :

  - version 9.0.1 through 9.0.1 Fix Pack 7 Interim Fix 2
  - version 9.0 through 9.0 Interim Fix 7");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6087");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# Check the version of Domino installed.
app_name = 'IBM Domino';
ver = get_kb_item_or_exit('Domino/Version');
port = get_kb_item('Domino/Version_provided_by_port');
if (!port) port = 0;
version = NULL;
fix = NULL;
fix_ver = NULL;
fix_pack = NULL;

#Customers who remain on the following releases may open a Service Request
#with IBM Support and reference SPR# DKEN9WGMYE for a custom hotfix:
#  IBM Domino 9.0 through 9.0 Interim Fix 7  (http://www-01.ibm.com/support/docview.wss?uid=swg21653364)
#  IBM Domino 9.0.1 through 9.0.1 Fix Pack 7 Interim Fix 2 (http://www-01.ibm.com/support/docview.wss?uid=swg21657963)
function might_have_custom_fix(ver)
{
  var item;
  if(ver =~ "^9\.0(\.0)?($|[^0-9])" && "FP" >!< ver)
  {
    item = pregmatch(pattern:"HF([\d]+)($|[^\d])", string:ver);

    if(!item)
      return TRUE;
    if(int(item[1]) <= 1139)
      return TRUE;

    return FALSE;
  }
  else if(ver =~ "^9\.0\.1($|[^0-9])" && (ver =~ "FP[1-7]($|[^\d])" || "FP" >!< ver))
  {
    if(ver =~ "FP[1-6]($|[^\d])")
      return TRUE;

    # FP7 running less than IF2
    item = pregmatch(pattern:"HF([\d]+)($|[^\d])", string:ver);
    if(!item)
      return TRUE;
    if(int(item[1]) <= 155)
      return TRUE;
    return FALSE;
  }
  else return FALSE;
}

if (might_have_custom_fix(ver:ver) && report_paranoia < 2) audit(AUDIT_PARANOID); 

# Ensure sufficient granularity.
if (ver !~ "^(\d+\.){1,}\d+.*$") audit(AUDIT_VER_NOT_GRANULAR, app_name, port, ver);

# No patches for 8.5.x yet, and based on this : www-01.ibm.com/support/docview.wss?uid=swg21611954
# I don't think there will be
if (ver =~ "^9\.0(\s|$)" || ver =~ "^9\.0\.[01]($|[^0-9])" || ver =~ "^8\.5\.[123]($|[^0-9])")
{
  fix = '9.0.1 FP8';
  fix_ver = '9.0.1';
  fix_pack = 8;
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);

# Breakdown the version into components.
version = pregmatch(string:ver, pattern:"^((?:\d+\.){1,}\d+)(?: FP(\d+))?(?: ?HF(\d+))?$");
if (isnull(version)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Use 0 if no FP number. Version number itself was
# checked for in the granularity check.
if (!version[2]) version[2] = 0;
else version[2] = int(version[2]);

# Compare current to fix and report as needed.
if (
  ver_compare(ver:version[1], fix:fix_ver, strict:FALSE) == -1 ||
  (ver =~ "^9\.0\.1($|[^0-9])" && version[2] < fix_pack)
)
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n' +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, ver);
