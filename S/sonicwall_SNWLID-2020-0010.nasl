#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141474);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-5135");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/05");
  script_xref(name:"CEA-ID", value:"CEA-2020-0127");

  script_name(english:"SonicWall SonicOS Buffer Overflow Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Buffer Overflow vulnerability, leading to Denial of Service, 
and potentially to Arbitrary Code Execution.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by a buffer overflow vulnerability, allowing a remote attacker to cause Denial of Service (DoS), 
and potentially execute arbitrary code by sending a malicious request to the firewall. 
This vulnerability affected SonicOS Gen 6 version 6.5.4.7, 6.5.1.12, 6.0.5.3, SonicOSv 6.5.4.v 
and Gen 7 version 7.0.0.0.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2020-0010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c667b9f5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

os = get_kb_item_or_exit("Host/OS");
if (os !~ "^SonicOS" ) audit(AUDIT_OS_NOT, "SonicWall SonicOS");

# SonicOS Enhanced 6.0.5.3-94o on a SonicWALL NSA 220
match = pregmatch(pattern:"^SonicOS(?: Enhanced)? (([0-9.]+)(-[^ ]*)?) on a SonicWALL", string:os);
if (isnull(match)) exit(1, "Failed to identify the version of SonicOS.");
version = match[1];

fix = NULL;


if (version =~ "^6\.")
{
  # SonicOS 6.0.5.3-93o and earlier
  # fixex in SonicOS 6.0.5.3-94o
  if (version =~ "^6\.0\.5\.3-([0-8]?[0-9]|9[0-3])o")
    fix = "6.0.5.3-94o"; 
  # SonicOS 6.5.1.11-4n and earlier
  # fixed in SonicOS 6.5.1.12-1n
  else if (version =~ "^6\.5\.1\.11-\d+n")
    fix = "SonicOS 6.5.1.12-1n";
  # SonicOS 6.5.4.7-79n and earlier
  # fixed in SonicOS 6.5.4.7-83n
  else if (version =~ "^6\.5\.4\.7-[0-7]?[0-9]n")
    fix = "6.5.4.7-83n";
  # SonicOSv 6.5.4.4-44v-21-794 and earlier
  # fixed in SonicOS 6.5.4.v-21s-987
  # XXX not sure how I can check for this version,
  # as version and fix formats look different
  #else if (version =~ "^6\.5\.4\.4")
  #  fix = "6.5.4.v-21s-987";
}
# SonicOS 7.0.0.0-1
# fixed in 7.0.0.0-2
else if (version =~ "^7\.0\.0\.0-[01]$")
{
  fix = "7.0.0.0-2";
}

if (isnull(fix))
  audit(AUDIT_DEVICE_NOT_VULN, "SonicWALL ", "SonicOS " + version);
#if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
else
{
  port = 0;
  report =
    '\n  Installed SonicOS version : ' + version +
    '\n  Fixed SonicOS version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}

