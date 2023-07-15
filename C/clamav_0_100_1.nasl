#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111517);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id("CVE-2017-16932", "CVE-2018-0360", "CVE-2018-0361");
  script_xref(name:"IAVB", value:"2018-B-0096");

  script_name(english:"ClamAV < 0.100.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon running on
the remote host is prior to 0.100.1. It is, therefore, affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://blog.clamav.net/2018/07/clamav-01001-has-been-released.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV version 0.100.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port    = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^0\.([0-9][0-9]\.[0-9]+|100\.0)$")
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.100.1' +
      '\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
