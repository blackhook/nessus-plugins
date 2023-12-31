#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-962.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19883);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2005-2871");
  script_xref(name:"FEDORA", value:"2005-962");

  script_name(english:"Fedora Core 3 : thunderbird-1.0.7-1.1.fc3 (2005-962)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes various bugs is now
available for Fedora Core 3.

This update has been rated as having important security impact by the
Fedora Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A bug was found in the way Thunderbird processes certain international
domain names. An attacker could create a specially crafted HTML file,
which when viewed by the victim would cause Thunderbird to crash or
possibly execute arbitrary code. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2005-2871
to this issue.

A bug was found in the way Thunderbird processes certain Unicode
sequences. It may be possible to execute arbitrary code as the user
running Thunderbird if the user views a specially crafted Unicode
sequence. (CVE-2005-2702)

A bug was found in the way Thunderbird makes XMLHttp requests. It is
possible that a malicious web page could leverage this flaw to exploit
other proxy or server flaws from the victim's machine. It is also
possible that this flaw could be leveraged to send XMLHttp requests to
hosts other than the originator; the default behavior of the browser
is to disallow this. (CVE-2005-2703)

A bug was found in the way Thunderbird implemented its XBL interface.
It may be possible for a malicious web page to create an XBL binding
in such a way that would allow arbitrary JavaScript execution with
chrome permissions. Please note that in Thunderbird 1.0.6 this issue
is not directly exploitable and will need to leverage other unknown
exploits. (CVE-2005-2704)

An integer overflow bug was found in Thunderbird's JavaScript engine.
Under favorable conditions, it may be possible for a malicious mail
message to execute arbitrary code as the user running Thunderbird.
Please note that JavaScript support is disabled by default in
Thunderbird. (CVE-2005-2705)

A bug was found in the way Thunderbird displays about: pages. It is
possible for a malicious web page to open an about: page, such as
about:mozilla, in such a way that it becomes possible to execute
JavaScript with chrome privileges. (CVE-2005-2706)

A bug was found in the way Thunderbird opens new windows. It is
possible for a malicious website to construct a new window without any
user interface components, such as the address bar and the status bar.
This window could then be used to mislead the user for malicious
purposes. (CVE-2005-2707)

A bug was found in the way Thunderbird processes URLs passed to it on
the command line. If a user passes a malformed URL to Thunderbird,
such as clicking on a link in an instant messaging program, it is
possible to execute arbitrary commands as the user running
Thunderbird. (CVE-2005-2968) 

Users of Thunderbird are advised to upgrade to this updated package
that contains Thunderbird version 1.0.7 and is not vulnerable to these
issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-September/001443.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19ff2ff9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"thunderbird-1.0.7-1.1.fc3")) flag++;
if (rpm_check(release:"FC3", reference:"thunderbird-debuginfo-1.0.7-1.1.fc3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
