#
# (C) Tenable Network Security, Inc,
#

include("compat.inc");

if (description)
{
  script_id(73947);
  script_version("1.5");
  script_cvs_date("Date: 2018/11/15 20:50:28");

  script_cve_id("CVE-2013-5016");
  script_bugtraq_id(67161);

  script_name(english:"Symantec Critical System Protection for Windows Security Bypass (SYM14-008)");
  script_summary(english:"Checks version of Symantec Critical System Protection");

  script_set_attribute(attribute:"synopsis", value:
"The remote windows host has a security application installed that is
potentially affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Critical System Protection installed on the
remote Windows host is a version prior to 5.2.9. It is, therefore,
potentially affected by a security bypass vulnerability. The default
policy settings are affected by a policy bypass when installed on an
unpatched Windows host.");
  # https://support.symantec.com/en_US/article.SYMSA1294.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0eadd6e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Critical System Protection 5.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:critical_system_protection");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("symantec_critical_system_protection_installed.nbin");
  script_require_keys("SMB/Symantec Critical System Protection/Path", "SMB/Symantec Critical System Protection/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Symantec Critical System Protection/Version");
path = get_kb_item_or_exit("SMB/Symantec Critical System Protection/Path");

if (ver_compare(ver:version, fix:'5.2.9', strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.2.9' +
      '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, 'Symantec Critical System Protection', version, path);
