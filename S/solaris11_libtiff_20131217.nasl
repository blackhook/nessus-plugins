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
  script_id(80681);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-4564", "CVE-2013-1960", "CVE-2013-1961");

  script_name(english:"Oracle Solaris Third-Party Patch Update : libtiff (cve_2012_4564_design_error1)");
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

  - ppm2tiff does not check the return value of the
    TIFFScanlineSize function, which allows remote attackers
    to cause a denial of service (crash) and possibly
    execute arbitrary code via a crafted PPM image that
    triggers an integer overflow, a zero-memory allocation,
    and a heap-based buffer overflow. (CVE-2012-4564)

  - Heap-based buffer overflow in the t2p_process_jpeg_strip
    function in tiff2pdf in libtiff 4.0.3 and earlier allows
    remote attackers to cause a denial of service (crash)
    and possibly execute arbitrary code via a crafted TIFF
    image file. (CVE-2013-1960)

  - Stack-based buffer overflow in the t2p_write_pdf_page
    function in tiff2pdf in libtiff before 4.0.3 allows
    remote attackers to cause a denial of service
    (application crash) via a crafted image length and
    resolution in a TIFF image file. (CVE-2013-1961)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/cve-2012-4564-design-error-vulnerability-in-libtiff"
  );
  # https://blogs.oracle.com/sunsecurity/multiple-buffer-errors-vulnerability-in-libtiff
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1aa2951"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.14.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:libtiff");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/17");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^libtiff$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.14.0.5.0", sru:"SRU 11.1.14.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : libtiff\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "libtiff");
