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
  script_id(80682);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4231", "CVE-2013-4232");

  script_name(english:"Oracle Solaris Third-Party Patch Update : libtiff (cve_2013_4231_buffer_overflow)");
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

  - Multiple buffer overflows in libtiff before 4.0.3 allow
    remote attackers to cause a denial of service
    (out-of-bounds write) via a crafted (1) extension block
    in a GIF image or (2) GIF raster image to
    tools/gif2tiff.c or (3) a long filename for a TIFF image
    to tools/rgb2ycbcr.c. NOTE: vectors 1 and 3 are disputed
    by Red Hat, which states that the input cannot exceed
    the allocated buffer size. (CVE-2013-4231)

  - Use-after-free vulnerability in the
    t2p_readwrite_pdf_image function in tools/ tiff2pdf.c in
    libtiff 4.0.3 allows remote attackers to cause a denial
    of service (crash) or possible execute arbitrary code
    via a crafted TIFF image. (CVE-2013-4232)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2013-4231-buffer-overflow-vulnerability-in-libtiff
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a36b86d"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2013-4232-resource-management-errors-vulnerability-in-libtiff
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59ad183b"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.15.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:libtiff");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
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

if (solaris_check_release(release:"0.5.11-0.175.1.15.0.4.0", sru:"SRU 11.1.15.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : libtiff\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "libtiff");
