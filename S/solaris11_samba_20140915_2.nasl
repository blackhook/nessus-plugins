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
  script_id(80769);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0244", "CVE-2014-3493");

  script_name(english:"Oracle Solaris Third-Party Patch Update : samba (multiple_vulnerabilities_in_samba1)");
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

  - The sys_recvfrom function in nmbd in Samba 3.6.x before
    3.6.24, 4.0.x before 4.0.19, and 4.1.x before 4.1.9
    allows remote attackers to cause a denial of service
    (infinite loop and CPU consumption) via a malformed UDP
    packet. (CVE-2014-0244)

  - The push_ascii function in smbd in Samba 3.6.x before
    3.6.24, 4.0.x before 4.0.19, and 4.1.x before 4.1.9
    allows remote authenticated users to cause a denial of
    service (memory corruption and daemon crash) via an
    attempt to read a Unicode pathname without specifying
    use of Unicode, leading to a character-set conversion
    failure that triggers an invalid pointer dereference.
    (CVE-2014-3493)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/multiple-vulnerabilities-in-samba
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbca196e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.1.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");

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

if (solaris_check_release(release:"0.5.11-0.175.2.1.0.5.0", sru:"SRU 11.2.1.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : samba\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_note(port:0, extra:error_extra);
  else security_note(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "samba");
