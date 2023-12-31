#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-13592.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43592);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-4376", "CVE-2009-4377", "CVE-2009-4378");
  script_bugtraq_id(37407);
  script_xref(name:"FEDORA", value:"2009-13592");

  script_name(english:"Fedora 12 : wireshark-1.2.5-3.fc12 (2009-13592)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various fixes were provided in wireshark 1.2.5 - see
http://www.wireshark.org/docs/relnotes/wireshark-1.2.5.html for more
details. Enhancements - introduced -devel package with autoconf
support - enable Lua support Fedora Bug Fixes - the root warning
dialog no longer shows up The following vulnerabilities have been
fixed. See the security advisory for details and a workaround.
http://www.wireshark.org/security/wnpa- sec-2009-09.html - The
Daintree SNA file parser could overflow a buffer. (Bug 4294)
CVE-2009-4376 - The SMB and SMB2 dissectors could crash. (Bug 4301)
CVE-2009-4377 - The IPMI dissector could crash on Windows. (Bug 4319)
The following bugs have been fixed: - Wireshark does not graph rtp
streams. (Bug 3801) - Wireshark showing extraneous data in a TCP
stream. (Bug 3955) - Wrong decoding of gtp.target identification. (Bug
3974) - TTE dissector bug. (Bug 4247) - Upper case in Lua pref symbol
causes Wireshark to crash. (Bug 4255) - OpenBSD 4.5 build fails at
epan/dissectors/packet-rpcap.c. (Bug 4258) - Incorrect display of
stream data using 'Follow tcp stream' option. (Bug 4288) - Custom
RADIUS dictionary can cause a crash. (Bug 4316) Updated Protocol
Support - DAP, eDonkey, GTP, IPMI, MIP, RADIUS, RANAP, SMB, SMB2, TCP,
TTE, VNC, X.509sat Updated Capture File Support - Daintree SNA.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.wireshark.org/docs/relnotes/wireshark-1.2.5.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/docs/relnotes/wireshark-1.2.5.html"
  );
  # http://www.wireshark.org/security/wnpa-
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.wireshark.org/security/wnpa-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=549578"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/033057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?776b44cb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wireshark package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"wireshark-1.2.5-3.fc12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark");
}
