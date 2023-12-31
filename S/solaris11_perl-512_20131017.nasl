#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80727);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-5195", "CVE-2012-5526", "CVE-2012-6329");

  script_name(english:"Oracle Solaris Third-Party Patch Update : perl-512 (cve_2012_5195_heap_buffer)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Heap-based buffer overflow in the Perl_repeatcpy
    function in util.c in Perl 5.12.x before 5.12.5, 5.14.x
    before 5.14.3, and 5.15.x before 15.15.5 allows
    context-dependent attackers to cause a denial of service
    (memory consumption and crash) or possibly execute
    arbitrary code via the 'x' string repeat operator.
    (CVE-2012-5195)

  - CGI.pm module before 3.63 for Perl does not properly
    escape newlines in (1) Set-Cookie or (2) P3P headers,
    which might allow remote attackers to inject arbitrary
    headers into responses from applications that use
    CGI.pm. (CVE-2012-5526)

  - The _compile function in Maketext.pm in the
    Locale::Maketext implementation in Perl before 5.17.7
    does not properly handle backslashes and fully qualified
    method names during compilation of bracket notation,
    which allows context-dependent attackers to execute
    arbitrary commands via crafted input to an application
    that accepts translation strings from users, as
    demonstrated by the TWiki application before 5.1.3, and
    the Foswiki application 1.0.x through 1.0.10 and 1.1.x
    through 1.1.6. (CVE-2012-6329)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/cve-2012-5195-heap-buffer-overrun-vulnerability-in-perl"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2012-5526-configuration-vulnerability-in-perl
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?975ebb1f"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2012-6329-code-injection-vulnerability-in-perl
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0ed10ce"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.7.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:perl-512");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^perl-512$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-512");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.7.0.5.0", sru:"SRU 11.1.7.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : perl-512\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "perl-512");
