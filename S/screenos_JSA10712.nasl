#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87539);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-7754");
  script_bugtraq_id(79627);
  script_xref(name:"JSA", value:"JSA10712");

  script_name(english:"Juniper ScreenOS 6.3.0r20 SSH ssh-pka SSH Negotiation RCE (JSA10712)");
  script_summary(english:"Checks version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Juniper ScreenOS version 6.3.0r20. It is,
therefore, affected by a remote code execution vulnerability due to
improper handling of specially crafted SSH negotiations when ssh-pka
is configured. An unauthenticated, remote attacker can exploit this to
cause a denial of service condition or the execution of arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10712");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS 6.3.0r21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("screenos_version.nbin");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
rspv = get_kb_item("Host/Juniper/ScreenOS/respin_version");

# Only 6.3.0r20 Affected
if (display_version !~ "^6\.3\.0r20($|[^0-9])")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);

# 6.3.0r20 respins are unlikely to exist but in case they do
# they're probably not affected
if (!isnull(rspv))
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);


port = 0;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : 6.3.0r21' +
    '\n';
  security_hole(extra:report, port:port);
}
else security_hole(port);
