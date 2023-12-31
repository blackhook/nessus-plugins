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
  script_id(80704);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2751", "CVE-2013-1915");

  script_name(english:"Oracle Solaris Third-Party Patch Update : modsecurity (cve_2012_2751_improper_input)");
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

  - ModSecurity before 2.6.6, when used with PHP, does not
    properly handle single quotes not at the beginning of a
    request parameter value in the Content-Disposition field
    of a request with a multipart/form-data Content-Type
    header, which allows remote attackers to bypass
    filtering rules and perform other attacks such as
    cross-site scripting (XSS) attacks. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2009-5031. (CVE-2012-2751)

  - ModSecurity before 2.7.3 allows remote attackers to read
    arbitrary files, send HTTP requests to intranet servers,
    or cause a denial of service (CPU and memory
    consumption) via an XML external entity declaration in
    conjunction with an entity reference, aka an XML
    External Entity (XXE) vulnerability. (CVE-2013-1915)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2012-2751-improper-input-validation-vulnerability-in-modsecurity
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0491cdf3"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2013-1915-input-validation-vulnerability-in-modsecurity
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17cc9506"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:modsecurity");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/31");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^modsecurity$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "modsecurity");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.0.0.0.0", sru:"11.2 SRU 0") > 0) flag++;

if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  error_extra = 'Affected package : modsecurity\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "modsecurity");
