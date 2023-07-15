#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103673);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7659",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-1000364"
  );
  script_bugtraq_id(
    99130,
    99132,
    99134,
    99135,
    99137,
    99170
  );
  script_xref(name:"IAVA", value:"2017-A-0288-S");

  script_name(english:"FireEye Operating System Multiple Vulnerabilities (AX < 7.7.7 / EX < 8.0.1)");
  script_summary(english:"Checks the version of FEOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FireEye Operating System
(FEOS) that is affected by multiple vulnerabilities. See vendor release notes for details.");
  # https://insinuator.net/2017/09/fireeye-security-bug-connection-to-physical-host-and-adjacent-network-possible-during-analysis-in-live-mode/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd3c01c0");
  script_set_attribute(attribute:"see_also", value:"https://docs.fireeye.com/docs/docs_en/AX/sw/7.7.7/RN/AX_RN_7.7.7_en.pdf");
  script_set_attribute(attribute:"see_also", value:"https://docs.fireeye.com/docs/docs_en/EX/sw/8.0.1/RN/EX_RN_8.0.1_en.pdf");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor release notes.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fireeye:feos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fireeye_os_version.nbin");
  script_require_keys("Host/FireEye/series", "Host/FireEye/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FireEye OS";
series = get_kb_item_or_exit("Host/FireEye/series");
version = get_kb_item_or_exit("Host/FireEye/version");

if (series == "EX") fix = "8.0.1";
else if (series == "AX") fix = "7.7.7";
else audit(AUDIT_DEVICE_NOT_VULN, "FireEye "+series);

report =
      '\n  Series            : ' + series +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : report
  );
  exit(0);
}

else audit(AUDIT_DEVICE_NOT_VULN, "FireEye "+series, version);
