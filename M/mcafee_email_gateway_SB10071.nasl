#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73832);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"MCAFEE-SB", value:"SB10071");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"McAfee Email Gateway OpenSSL Information Disclosure (SB10071) (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of McAfee Email Gateway (MEG)
that is affected by an information disclosure due to a flaw in the
OpenSSL library, commonly known as the Heartbleed bug. An attacker
could potentially exploit this vulnerability repeatedly to read up to
64KB of memory from the device.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10071");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix referenced in the vendor advisory.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:email_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_email_gateway_version.nbin");
  script_require_keys("Host/McAfeeSMG/name", "Host/McAfeeSMG/version", "Host/McAfeeSMG/patches");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = get_kb_item_or_exit("Host/McAfeeSMG/name");
version = get_kb_item_or_exit("Host/McAfeeSMG/version");
patches = get_kb_item_or_exit("Host/McAfeeSMG/patches");

# Determine fix.
if (version =~ "^7\.5\.")
{
  fix = "7.5.2846.114";
  hotfix = "7.5h960401";
}
else if (version =~ "^7\.6\.")
{
  fix = "7.6.2810.114";
  hotfix = "7.6h960405";
}
else audit(AUDIT_INST_VER_NOT_VULN, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1 && hotfix >!< patches)
{
  port = 0;

  if (report_verbosity > 0)
  {
    report = '\n' + app_name + ' ' + version + ' is missing patch ' + hotfix + '.\n';
    security_warning(extra:report, port:port);
  }
  else security_warning(port:port);
  exit(0);
}
else audit(AUDIT_PATCH_INSTALLED, hotfix);
