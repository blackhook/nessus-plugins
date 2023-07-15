#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150981);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-20019");
  script_xref(name:"CEA-ID", value:"CEA-2021-0030");

  script_name(english:"SonicWall SonicOS Buffer Overflow (SNWLID-2021-0006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a Buffer Overflow vulnerability, leading to partial Memory Leak.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by a buffer overflow vulnerability. A vulnerability in SonicOS where the HTTP server response leaks partial memory by 
sending a crafted unauthenticated HTTP request. This can potentially lead to an internal sensitive data disclosure 
vulnerability. This vulnerability affected SonicOS Gen 6 version 6.5.4.7-83n, 6.5.1.12-3n and 6.0.5.3-94o, SonicOSv 
6.5.4.4-44v-21-955, and Gen 7 version 7.0.0-R713 and earlier, 7.0.1-R1036 and earlier, and below SonicOS - 7.0.0.376.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2021-0006
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e42eda8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20019");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}

var os = get_kb_item_or_exit('Host/OS');
if (os !~ "^SonicOS" ) audit(AUDIT_OS_NOT, 'SonicWall SonicOS');

# SonicOS Enhanced 6.0.5.3-94o on a SonicWALL NSA 220
var match = pregmatch(pattern:"^SonicOS(?: Enhanced)? ([0-9.]+)(-[^ ]*)? on a SonicWALL (.*)$", string:os);
if (isnull(match)) exit(1, 'Failed to identify the version of SonicOS.');
var version = match[1];
var ext = match[2];
var model = match[3];

var full_ver = version + ext;

if (!empty_or_null(ext))
  ext = ext - '-';
else
  ext = '';

var fix = NULL;

# GEN6: 
# - NSa, TZ, SOHO W, SuperMassive 92xx/94xx/96xx (6.5.4.8-83n and older, fixed in 6.5.4.8-89n)
# - NSsp 12K, SuperMassive 9800 (6.5.1.12-3n and older, fixed in Pending Release)
# - SuperMassive 10k (6.0.5.3-94o and older, fixed in Pending Release)
# - NSv (Virtual: VMWare/Hyper-V/AWS/Azure/KVM) (SonicOSv - 6.5.4.4-44v-21-955 and older, fixed in 6.5.4.4-44v-21-1288)
if (version =~ "^6\.")
{
  # SonicOS 6.0.5.3-94o and earlier
  # Pending Release, check vendor advisory
  if ((version =~ "^6\.0\.5\.3") && (ext =~ "^([0-8]?[0-9]|9[0-4])o") && (model =~ "^SuperMassive 10"))
    fix = 'Check vendor advisory'; 
  # SonicOS 6.5.1.12-3n and earlier
  # Pending Release, check vendor advisory
  else if ((version =~ "^6\.5\.1\.12") && (ext =~ "^[0-3]n") && (model =~ "^(SuperMassive 9800|NSSP 12)"))
    fix = 'Check vendor advisory';
  # SonicOS 6.5.4.8-83n and earlier
  # fixed in SonicOS 6.5.4.8-89n
  else if ((version =~ "^6\.5\.4\.8") && (ext =~ "^([0-7]?[0-9]|8[0-3])n") && (model =~ "^(NSA|TZ|SOHO|SuperMassive 9[246][0-9][0-9])"))
    fix = '6.5.4.8-89n';
  # cannot check for NSv Virtual platform SonicOSv - 6.5.4.4-44v-21-955 and older
}
# GEN7
# - NSa, TZ, NSsp
# - NSv
else if (version =~ "^7\.")
{
  # maybe use (ver_compare(ver:version,fix:fix,strict:FALSE) < 0)
  if (version =~ "7\.0\.0" && model =~ "(NSA|TZ)" && (ver_compare(ver:ext,fix:'714',strict:FALSE) < 0))
    fix = '7.0.0-R906 and later, 7.0.1-R1456';
  else if (model =~ "NSSP" && (ver_compare(ver:version,fix:'7.0.0.376',strict:FALSE) < 0))
    fix = '7.0.0.376 and later, 7.0.1-R579';
  # cannot check for NSv Virtual platform NSsp- 7.0.1-R1036 and older
}

if (isnull(fix))
  audit(AUDIT_DEVICE_NOT_VULN, 'SonicWALL ' + model, 'SonicOS ' + full_ver);
else
{
  var port = 0;
  var report =
    '\n  Installed SonicOS version : ' + full_ver +
    '\n  Fixed SonicOS version     : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}

