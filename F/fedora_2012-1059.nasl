#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-1059.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(57986);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-0813");
  script_bugtraq_id(51703);
  script_xref(name:"FEDORA", value:"2012-1059");

  script_name(english:"Fedora 16 : wicd-1.7.0-10.fc16 (2012-1059)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2012-0813

A sensitive information disclosure flaw was found in the way wicd,
wireless and wired network connection manager, performed management of
sensitive information, to be stored in log files. Fields like
'password', 'identity', 'private_key', 'private_key_passwd' etc., were
not excluded from being logged into /var/log/wicd log file, which
could allow local attacker, with the privileges of the 'adm' group to
view content of these entities in plain text, leading to information
disclosure. This update fixes the problem.

A reboot is not technically necessary, but if you do not reboot your
system after installing this update, you should at least restart the
wicd service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=785147"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-February/073375.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbb1f636"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected wicd package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wicd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"wicd-1.7.0-10.fc16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wicd");
}
