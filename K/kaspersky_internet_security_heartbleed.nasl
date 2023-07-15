#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77437);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");

  script_name(english:"Kaspersky Internet Security Heartbeat Information Disclosure (Heartbleed)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Kaspersky Internet Security (KIS)
installed that is missing a vendor patch. It is, therefore, affected
by an information disclosure vulnerability.

An out-of-bounds read error, known as the 'Heartbleed Bug', exists
related to handling TLS heartbeat extensions that could allow an
attacker to obtain sensitive information such as primary key material,
secondary key material, and other protected content.");
  script_set_attribute(attribute:"see_also", value:"https://support.kaspersky.com/10235#block1");
  script_set_attribute(attribute:"see_also", value:"https://support.kaspersky.com/us/8049#patches");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Kaspersky Internet Security 13.0.1.4190 Patch K /
14.0.0.4651 Patch G or later.

In the case of other versions, please contact the vendor for guidance.");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaspersky:kaspersky_internet_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("installed_sw/Kaspersky Internet Security");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Kaspersky Internet Security";
get_install_count(app_name:app_name, exit_if_zero:TRUE);
fix = NULL;

# Only 1 install of the server is possible.
install = get_single_install(app_name:app_name);
path    = install['path'];

# Verify ssleay32.dll prodversion
dll = hotfix_append_path(path:path, value:"ssleay32.dll");
version_data = hotfix_get_pversion(path:dll);
hotfix_check_fversion_end();
# Handle error; omit app_name param to
# get appropriate exit message.
hotfix_handle_error(
  error_code   : version_data['error'],
  file         : dll,
  exit_on_fail : TRUE
);

dll_ver = version_data['value'];

# Check ssleay32.dll version
if (dll_ver =~ "^1\.0\.1[a-f]")
{
  port = kb_smb_transport();
  if (report_verbosity > 0)
  {
    report =
    '\n  File              : ' + dll +
    '\n  Installed version : ' + dll_ver +
    '\n  Fixed version     : 1.0.1g' +
    '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name + " OpenSSL file", dll_ver, dll);
