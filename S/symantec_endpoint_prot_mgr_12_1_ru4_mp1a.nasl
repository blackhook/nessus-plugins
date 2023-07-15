#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73964);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU4 MP1a OpenSSL Heartbeat Information Disclosure (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Symantec
Endpoint Protection Manager (SEPM) installed on the remote host is
affected by an out-of-bounds read error, known as the 'Heartbleed Bug'
in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content. Note
this affects both client and server modes of operation.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.TECH216558.html");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 12.1 RU4 MP1a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0160");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("SMB/sep_manager/path", "SMB/sep_manager/ver");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('SMB/sep_manager/ver');
path        = get_kb_item_or_exit('SMB/sep_manager/path');

# Versions 12.1 RU2 (12.1.2015.2015) to SEPM 12.1 RU4 MP1 (12.1.4100.4126) are vulnerable
lower_cutoff  = "12.1.2015.2015";
higher_cutoff = "12.1.4100.4126";

if (
  ver_compare(ver:display_ver, fix:lower_cutoff, strict:FALSE) >= 0 &&
  ver_compare(ver:display_ver, fix:higher_cutoff, strict:FALSE) <= 0
)
{
  fixed_ver = "12.1.4104.4130 (12.1 RU4 MP1a)";

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+ path +
      '\n  Installed version : '+ display_ver +
      '\n  Fixed version     : '+ fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Endpoint Protection Manager', display_ver, path);
