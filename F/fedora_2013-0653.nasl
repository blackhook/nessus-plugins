#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-0653.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63624);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(57193, 57194, 57195, 57196, 57197, 57198, 57199, 57203, 57204, 57205, 57207, 57209, 57211, 57213, 57215, 57217, 57218, 57228, 57232, 57234, 57235, 57236, 57238, 57240, 57241, 57244, 57258);
  script_xref(name:"FEDORA", value:"2013-0653");

  script_name(english:"Fedora 17 : thunderbird-17.0.2-1.fc17 (2013-0653)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Security fixes can be found here:
    http://www.mozilla.org/security/known-vulnerabilities/th
    underbird.html#thunderbird17.0.2

    - An issue that caused occasional corruption in local
      folders after filtering is now fixed (815012)

    - An issue that caused deletion of drafts saved in IMAP
      folders whilst in offline mode is now fixed (805626)
      More info about release :

  -
    http://www.mozilla.org/en-US/thunderbird/16.0.2/releasen
    otes/

    - Vulnerability outlined here:
      https://blog.mozilla.org/security/2012/10/10/security-
      vulnerability-in-firefox-16/

    - Vulnerability outlined here:
      https://blog.mozilla.org/security/2012/10/10/security-
      vulnerability-in-firefox-16/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/en-US/thunderbird/16.0.2/releasenotes/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa274ce8"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird.html#thunderbird17.0.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71f70848"
  );
  # https://blog.mozilla.org/security/2012/10/10/security-vulnerability-in-firefox-16/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc43f3c3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-January/097085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?688ebc20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox XMLSerializer Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"thunderbird-17.0.2-1.fc17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
