#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95925);
  script_version("1.5");
  script_cvs_date("Date: 2019/01/02 11:18:37");


  script_name(english:"Palo Alto Networks PAN-OS 7.0.x < 7.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.0.x prior to 7.0.12. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists when processing
    IPv6 traffic matching a predict session. An
    unauthenticated, remote attacker can exploit this to
    cause the dataplane to restart.

  - A denial of service vulnerability exists under the HA
    active-active configuration when handling out-of-order
    jumbo packets. An unauthenticated, remote attacker can
    exploit this to cause a failover to occur.

  - A denial of service vulnerability exists when processing
    packets that have an incorrectly set IPv4 Reserved flag.
    An unauthenticated, remote attacker can exploit this to
    cause the dataplane to restart.");
# https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os-release-notes/pan-os-7-0-12-addressed-issues
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ffd409");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = '7.0.12';

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# 7.0.x is affected.
if (version !~ "^7\.0($|[^0-9])") audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# Compare version to vuln and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + full_version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
