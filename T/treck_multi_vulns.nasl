#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137702);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2020-11896",
    "CVE-2020-11897",
    "CVE-2020-11898",
    "CVE-2020-11899",
    "CVE-2020-11900",
    "CVE-2020-11901",
    "CVE-2020-11902",
    "CVE-2020-11903",
    "CVE-2020-11904",
    "CVE-2020-11905",
    "CVE-2020-11906",
    "CVE-2020-11907",
    "CVE-2020-11908",
    "CVE-2020-11909",
    "CVE-2020-11910",
    "CVE-2020-11911",
    "CVE-2020-11912",
    "CVE-2020-11913",
    "CVE-2020-11914"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0052");

  script_name(english:"Treck TCP/IP stack multiple vulnerabilities. (Ripple20)");

  script_set_attribute(attribute:"synopsis", value:
"The Treck network stack used by the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"This plugin detects the usage of the Treck TCP/IP stack by the host thereby indicating that it could be potentially
vulnerable to the Ripple20 vulnerabilities. Patches are being slowly rolled out by vendors and we will release plugins
for patches as they are released by the vendors. In the interim, if you have applied the patches from the vendor for the
Ripple20 vulnerabilities on this host, please recast the severity of this plugin.

Note: This plugin requires ICMP traffic to be unblocked between the scanner and the host");
  script_set_attribute(attribute:"see_also", value:"https://www.jsof-tech.com/ripple20/");
  # https://www.jsof-tech.com/wp-content/uploads/2020/06/JSOF_Ripple20_Technical_Whitepaper_June20.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?431098c1");
  script_set_attribute(attribute:"see_also", value:"https://support.hp.com/emea_africa-en/document/c06640149");
  script_set_attribute(attribute:"see_also", value:"https://psirt.bosch.com/security-advisories/BOSCH-SA-662084.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches as they become available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:treck:tcp_ip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("treck_detect.nbin", "treck_detect2.nbin", "treck_ip_opt7.nbin", "ssh_get_info.nasl", "os_fingerprint.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
  script_require_keys("treck_network_stack");

  exit(0);
}

##
# Determine if we've got Cisco
# @return TRUE if we're reasonably confident the target is Cisco, otherwise FALSE.
##
function is_cisco()
{
  local_var cisco_list, os, confidence, cisco_model, cisco_model_desc;

  # Check if local detections look like Cisco
  cisco_list = get_kb_list('Host/Cisco/*');

  if (!empty_or_null(cisco_list))
    return TRUE;

  # If we're relatively confident it's Cisco, return TRUE
  os = toupper(get_kb_item('Host/OS'));
  confidence = get_kb_item('Host/OS/Confidence');
  if ('CISCO' >< os && confidence >= 75)
    return TRUE;

  # If SNMP looks like it's Cisco, return TRUE
  cisco_model = get_kb_item('CISCO/model');
  cisco_model_desc = get_kb_item('CISCO/model_desc');
  if (!empty_or_null(cisco_model) && !empty_or_null(cisco_model_desc))
    return TRUE;

  return FALSE;
}

##
# Determine if we've got StarOS
# @return TRUE if the target looks at all like StarOS, otherwise FALSE.
##
function is_staros()
{
  local_var os, cisco_model, cisco_model_desc;

  # If we locally detected StarOS, return TRUE
  if(get_kb_item('Host/Cisco/StarOS'))
    return TRUE;

  # If the OS is StarOS, return TRUE
  os = toupper(get_kb_item('Host/OS'));
  if ('STAROS' >< os)
    return TRUE;

  # If SNMP looks like it's a StarOS device, return TRUE
  cisco_model = get_kb_item('CISCO/model');
  cisco_model_desc = get_kb_item('CISCO/model_desc');

  if (!empty_or_null(cisco_model) && cisco_model =~ "ciscoASR5[50]00")
    return TRUE;
  if (!empty_or_null(cisco_model_desc) && cisco_model_desc =~ "Cisco Systems ASR5[50]00")
    return TRUE;

  return FALSE;
}

get_kb_item_or_exit('treck_network_stack');


if (!is_cisco() || is_staros())
{
  report = '\n  Detected Treck TCP\\IP network stack.';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else
  audit(AUDIT_HOST_NOT, 'a vulnerable Cisco product');

