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
  script_id(80759);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2125", "CVE-2012-2126");

  script_name(english:"Oracle Solaris Third-Party Patch Update : rubygems (cve_2012_2125_https_to)");
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

  - RubyGems before 1.8.23 can redirect HTTPS connections to
    HTTP, which makes it easier for remote attackers to
    observe or modify a gem during installation via a
    man-in-the-middle attack. (CVE-2012-2125)

  - RubyGems before 1.8.23 does not verify an SSL
    certificate, which allows remote attackers to modify a
    gem during installation via a man-in-the-middle attack.
    (CVE-2012-2126)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/cve-2012-2125-https-to-http-redirection-vulnerability-in-rubygems"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2012-2126-cryptographic-issues-vulnerability-in-rubygems
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d4ec26e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.21.4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:rubygems");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^rubygems$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygems");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.21.0.4.1", sru:"SRU 11.1.21.4.1") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : rubygems\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "rubygems");
