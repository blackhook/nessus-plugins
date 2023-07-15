#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106197);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2018-0014");
  script_xref(name:"JSA", value:"JSA10841");

  script_name(english:"Juniper ScreenOS < 6.3.0r25 Etherleak Vulnerability (JSA10841)");
  script_summary(english:"Checks the version of ScreenOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information leakage vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Juniper ScreenOS running on the remote host is 6.3.x
prior to 6.3.0r25. It is, therefore, affected by a flaw that may allow a
remote attacker (on the same network segment) to gain access to fragments
of system memory or data from previously submitted packets.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10841&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?200935bf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS version 6.3.0r25 or later. Alternatively,
apply the workaround referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:screenos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("screenos_version.nbin", "screenos_unsupported.nasl");
  script_require_keys("Host/Juniper/ScreenOS/display_version", "Host/Juniper/ScreenOS/version");
  script_exclude_keys("Host/Juniper/ScreenOS/unsupported");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Juniper ScreenOS";
display_version = get_kb_item_or_exit("Host/Juniper/ScreenOS/display_version");
version = get_kb_item_or_exit("Host/Juniper/ScreenOS/version");
if (get_kb_item("Host/Juniper/ScreenOS/unsupported"))
  exit(0, app_name + " version " + display_version + " is installed and no longer supported, therefore, it was not checked."); 

# prior to 6.3.0r25 are affected. 6.2 and prior are unsupported
# fix is 6.3.0r25 and later
if (ver_compare(ver:version, minver:"6.3.0.0", fix:"6.3.0.25", strict:FALSE) < 0)
{
  display_fix = "6.3.0r25";

  port = 0;
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + display_fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
