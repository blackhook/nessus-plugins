#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86604);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-5722", "CVE-2015-5986", "CVE-2015-7031");
  script_bugtraq_id(76605, 76618);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-10-21-8");

  script_name(english:"Mac OS X : OS X Server < 5.0.15 Multiple Vulnerabilities");
  script_summary(english:"Checks the OS X Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of OS X Server installed that
is prior to 5.0.15. It is, therefore, affected by the following
vulnerabilities :

  - A denial of service vulnerability exists due to an
    assertion flaw that is triggered when parsing malformed
    DNSSEC keys. An unauthenticated, remote attacker can
    exploit this, via a specially crafted query to a zone
    containing such a key, to cause a validating resolver to
    exit. (CVE-2015-5722)

  - A denial of service vulnerability exists in the
    fromwire_openpgpkey() function in openpgpkey_61.c that
    is triggered when the length of data is less than 1. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted response to a query, to cause an
    assertion failure that terminates named. (CVE-2015-5986)

  - A flaw exists in the web service component due to HTTP
    header field references missing from configuration files.
    A remote attacker can exploit this to bypass access
    restrictions. (CVE-2015-7031)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205376");
  # https://lists.apple.com/archives/security-announce/2015/Oct/msg00009.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?717081f4");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01287");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01291");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X Server version 5.0.15 or later.

Note that OS X Server 5.0.15 is available only for OS X 10.10.5 and
OS X 10.11.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "5.0.15";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
