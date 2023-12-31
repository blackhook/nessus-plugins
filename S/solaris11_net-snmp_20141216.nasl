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
  script_id(80708);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2141", "CVE-2014-2285", "CVE-2014-3565");

  script_name(english:"Oracle Solaris Third-Party Patch Update : net-snmp (cve_2012_2141_denial_of)");
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

  - The perl_trapd_handler function in
    perl/TrapReceiver/TrapReceiver.xs in Net-SNMP 5.7.3.pre3
    and earlier, when using certain Perl versions, allows
    remote attackers to cause a denial of service (snmptrapd
    crash) via an empty community string in an SNMP trap,
    which triggers a NULL pointer dereference within the
    newSVpv function in Perl. (CVE-2014-2285)

  - snmplib/mib.c in net-snmp 5.7.0 and earlier, when the

    -OQ option is used, allows remote attackers to cause a
    denial of service (snmptrapd crash) via a crafted SNMP
    trap message, which triggers a conversion to the
    variable type designated in the MIB file, as
    demonstrated by a NULL type in an ifMtu trap message.
    (CVE-2014-3565)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/sunsecurity/cve-2012-2141-denial-of-servicedos-vulnerability-in-net-snmp"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2014-2285-input-validation-vulnerability-in-net-snmp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2d7b7b7"
  );
  # https://blogs.oracle.com/sunsecurity/cve-2014-3565-resource-management-errors-vulnerability-in-net-snmp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a423e63d"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.2.5.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:net-snmp");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^net-snmp$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.2.5.0.5.0", sru:"SRU 11.2.5.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : net-snmp\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "net-snmp");
