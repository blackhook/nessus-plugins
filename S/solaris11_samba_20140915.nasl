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
  script_id(80768);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0178");

  script_name(english:"Oracle Solaris Third-Party Patch Update : samba (cve_2014_0178_information_disclosure)");
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

  - Samba 3.6.6 through 3.6.23, 4.0.x before 4.0.18, and
    4.1.x before 4.1.8, when a certain vfs shadow copy
    configuration is enabled, does not properly initialize
    the SRV_SNAPSHOT_ARRAY response field, which allows
    remote authenticated users to obtain potentially
    sensitive information from process memory via a (1)
    FSCTL_GET_SHADOW_COPY_DATA or (2)
    FSCTL_SRV_ENUMERATE_SNAPSHOTS request. (CVE-2014-0178)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2014-0178-information-disclosure-vulnerability-in-samba
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?157fe776"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.2.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:samba");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^samba$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.2.0.5.0", sru:"SRU 11.2.2.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : samba\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_note(port:0, extra:error_extra);
  else security_note(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "samba");
