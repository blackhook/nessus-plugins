#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91970);
  script_version("1.5");
  script_cvs_date("Date: 2019/01/02 11:18:37");


  script_name(english:"Palo Alto Networks PAN-OS 7.0.x < 7.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.0.x < 7.0.5. It is, therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service or the execution of arbitrary code.

  - A flaw exists in the API due to sending inappropriate
    responses to special requests. An unauthenticated,
    remote attacker can exploit this to have an unspecified
    impact.

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to access potentially sensitive
    information in the system logs.

  - A flaw exists in the firewall functionality due to
    session timeout values being ignored, which allows
    administrator sessions to be automatically refreshed.
    An unauthenticated, remote attacker can exploit this to
    more easily gain access to a user's session.

  - A flaw exists when handling mutated traffic from
    third-party signature detection software that causes a
    VM-Series disk to become corrupted and enter maintenance
    mode. An unauthenticated, remote attacker can exploit
    this to impact the integrity of the system.

  - A flaw exists in the firewall functionality that is
    triggered during the SSL handshake when the firewall
    receives a Hello packet from the server that has a
    higher SSL protocol version than the Hello packet
    received from the client. An unauthenticated, remote
    attacker can exploit this to cause the dataplane to
    restart, resulting in a denial of service condition.

  - A security bypass vulnerability exists in the XML API
    that allows an authenticated, remote attacker with
    superuser read-only permissions to bypass intended
    restrictions and perform a commit.

  - A flaw exists in the firewall functionality due to not
    accurately checking certificate revocation status via
    OSCP when the OCSP request does not include the HOST
    header option. An unauthenticated, remote attacker can
    exploit this to impact the integrity of the system.
");
  # https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os-release-notes/pan-os-7-0-5-addressed-issues#47759
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21ad624a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/07");

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
fix = '7.0.5';

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
