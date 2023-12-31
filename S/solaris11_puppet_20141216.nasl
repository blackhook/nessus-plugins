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
  script_id(80745);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3248", "CVE-2014-3250");

  script_name(english:"Oracle Solaris Third-Party Patch Update : puppet (multiple_vulnerabilities_in_puppet1)");
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

  - Untrusted search path vulnerability in Puppet Enterprise
    2.8 before 2.8.7, Puppet before 2.7.26 and 3.x before
    3.6.2, Facter 1.6.x and 2.x before 2.0.2, Hiera before
    1.3.4, and Mcollective before 2.5.2, when running with
    Ruby 1.9.1 or earlier, allows local users to gain
    privileges via a Trojan horse file in the current
    working directory, as demonstrated using (1)
    rubygems/defaults/ operating_system.rb, (2) Win32API.rb,
    (3) Win32API.so, (4) safe_yaml.rb, (5)
    safe_yaml/deep.rb, or (6) safe_yaml/deep.so; or (7)
    operatingsystem.rb, (8) operatingsystem.so, (9)
    osfamily.rb, or (10) osfamily.so in puppet/confine.
    (CVE-2014-3248)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/multiple-vulnerabilities-in-puppet
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e305605"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.5.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:puppet");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^puppet$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.5.0.5.0", sru:"SRU 11.2.5.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : puppet\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "puppet");
