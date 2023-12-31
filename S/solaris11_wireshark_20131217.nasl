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
  script_id(80810);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6339", "CVE-2013-6340");

  script_name(english:"Oracle Solaris Third-Party Patch Update : wireshark (multiple_vulnerabilities_in_wireshark8)");
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

  - The ieee802154_map_rec function in
    epan/dissectors/packet-ieee802154.c in the IEEE 802.15.4
    dissector in Wireshark 1.8.x before 1.8.11 and 1.10.x
    before 1.10.3 uses an incorrect pointer chain, which
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2013-6336)

  - Unspecified vulnerability in the NBAP dissector in
    Wireshark 1.8.x before 1.8.11 and 1.10.x before 1.10.3
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2013-6337)

  - The dissect_sip_common function in
    epan/dissectors/packet-sip.c in the SIP dissector in
    Wireshark 1.8.x before 1.8.11 and 1.10.x before 1.10.3
    does not properly initialize a data structure, which
    allows remote attackers to cause a denial of service
    (application crash) via a crafted packet.
    (CVE-2013-6338)

  - The dissect_openwire_type function in
    epan/dissectors/packet-openwire.c in the OpenWire
    dissector in Wireshark 1.8.x before 1.8.11 and 1.10.x
    before 1.10.3 allows remote attackers to cause a denial
    of service (loop) via a crafted packet. (CVE-2013-6339)

  - epan/dissectors/packet-tcp.c in the TCP dissector in
    Wireshark 1.8.x before 1.8.11 and 1.10.x before 1.10.3
    does not properly determine the amount of remaining
    data, which allows remote attackers to cause a denial of
    service (application crash) via a crafted packet.
    (CVE-2013-6340)"
  );
  # https://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a913f44"
  );
  # https://blogs.oracle.com/sunsecurity/multiple-vulnerabilities-in-wireshark
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ccbc2d4"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.14.5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:wireshark");

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

if (empty_or_null(egrep(string:pkg_list, pattern:"^wireshark$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.14.0.5.0", sru:"SRU 11.1.14.5.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : wireshark\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "wireshark");
