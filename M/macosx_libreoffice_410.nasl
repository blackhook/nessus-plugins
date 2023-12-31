#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73335);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id("CVE-2013-4156");
  script_bugtraq_id(61468);

  script_name(english:"LibreOffice < 3.6.7 / 4.0.4 / 4.1.0 .docm Import DoS (Mac OS X)");
  script_summary(english:"Checks version of LibreOffice");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A version of LibreOffice prior to 3.6.7 / 4.0.4 / 4.1.0 is installed
on the remote Mac OS X host. It is, therefore, reportedly affected by
a denial of service vulnerability.

A flaw exists in the .docm import filter that could cause a NULL
dereference. This could allow a remote attacker with a specially
crafted file to crash the application upon loading.

Note that Nessus has not attempted to exploit this issue, but has
instead relied only on the self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/about-us/security/advisories/cve-2013-4156/");
  # http://blog.documentfoundation.org/2013/07/18/the-document-foundation-announces-libreoffice-3-6-7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d85f7e6");
  # http://blog.documentfoundation.org/2013/06/19/the-document-foundation-announces-libreoffice-4-0-4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f743c734");
  # http://blog.documentfoundation.org/2013/07/25/libreoffice-4-1-interoperability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77ffc9e9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 3.6.7 / 4.0.4 / 4.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4156");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_libreoffice_installed.nasl");
  script_require_keys("MacOSX/LibreOffice/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/LibreOffice";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);

if (
  # nb: first release of LibreOffice was 3.3.0.
  version =~ "^3\.[3-5]\." ||
  (version =~ "^3\.6\." && ver_compare(ver:version, fix:'3.6.7.1', strict:FALSE) == -1) ||
  (version =~ "^4\.0\." && ver_compare(ver:version, fix:'4.0.4.1', strict:FALSE) == -1) ||
  (version =~ "^4\.1\." && ver_compare(ver:version, fix:'4.1.0.1', strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.6.7 / 4.0.4 / 4.1.0\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "LibreOffice", version, path);
