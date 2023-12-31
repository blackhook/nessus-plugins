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
  script_id(80589);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4352", "CVE-2014-0117", "CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");

  script_name(english:"Oracle Solaris Third-Party Patch Update : apache (multiple_denial_of_service_dos5)");
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

  - The cache_invalidate function in
    modules/cache/cache_storage.c in the mod_cache module in
    the Apache HTTP Server 2.4.6, when a caching forward
    proxy is enabled, allows remote HTTP servers to cause a
    denial of service (NULL pointer dereference and daemon
    crash) via vectors that trigger a missing hostname
    value. (CVE-2013-4352)

  - The mod_proxy module in the Apache HTTP Server 2.4.x
    before 2.4.10, when a reverse proxy is enabled, allows
    remote attackers to cause a denial of service
    (child-process crash) via a crafted HTTP Connection
    header. (CVE-2014-0117)

  - The deflate_in_filter function in mod_deflate.c in the
    mod_deflate module in the Apache HTTP Server before
    2.4.10, when request body decompression is enabled,
    allows remote attackers to cause a denial of service
    (resource consumption) via crafted request data that
    decompresses to a much larger size. (CVE-2014-0118)

  - Race condition in the mod_status module in the Apache
    HTTP Server before 2.4.10 allows remote attackers to
    cause a denial of service (heap-based buffer overflow),
    or possibly obtain sensitive credential information or
    execute arbitrary code, via a crafted request that
    triggers improper scoreboard handling within the
    status_handler function in
    modules/generators/mod_status.c and the
    lua_ap_scoreboard_worker function in
    modules/lua/lua_request.c. (CVE-2014-0226)

  - The mod_cgid module in the Apache HTTP Server before
    2.4.10 does not have a timeout mechanism, which allows
    remote attackers to cause a denial of service (process
    hang) via a request to a CGI script that does not read
    from its stdin file descriptor. (CVE-2014-0231)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/multiple-denial-of-servicedos-vulnerabilities-in-apache-http-server
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?104d170e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.2.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:apache");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^apache-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.2.0.5.0", sru:"SRU 11.2.2.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : apache\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "apache");
