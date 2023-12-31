#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76280);
  script_version("1.3");
  script_cvs_date("Date: 2018/07/27 18:38:14");

  script_cve_id("CVE-2014-3814");
  script_bugtraq_id(68099, 68100);
  script_xref(name:"IAVB", value:"2014-B-0082");

  script_name(english:"Juniper ScreenOS 6.3 < 6.3.0r17 IPv6 Packet DoS");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Juniper ScreenOS 6.3 prior to
6.3.0r17. It is, therefore, affected by a denial of service
vulnerability.

A denial of service flaw exists when handling a specially crafted IPv6
packet sequence. This could allow a remote attacker to cause the
device to crash or reboot, and repeated exploitation can result in an
extended denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10632");
  script_set_attribute(attribute:"solution", value:"Upgrade to 6.3.0r17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");

display_fix = "6.3.0r17";
fix = str_replace(string:display_fix, find:'r', replace:'.');

# Only treat 6.3.x as affected.
if (version =~ "^6\.3\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_version +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
