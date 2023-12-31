#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-15390.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79897);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/28");

  script_cve_id("CVE-2014-3566");
  script_xref(name:"FEDORA", value:"2014-15390");

  script_name(english:"Fedora 19 : libuv-0.10.29-1.fc19 / nodejs-0.10.33-1.fc19 (2014-15390) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This release handles the recent POODLE vulnerability by disabling
SSLv2/SSLv3 by default for the most predominate uses of TLS in
Node.js.

It took longer than expected to get this release accomplished in a way
that would provide appropriate default security settings, while
minimizing the surface area for the behavior change we were
introducing. It was also important that we validated that our changes
were being applied in the variety of configurations we support in our
APIs.

With this release, we are confident that the only behavior change is
that of the default allowed protocols do not include SSLv2 or SSLv3.
Though you are still able to programatically consume those protocols
if necessary.

Included is the documentation that you can find at
https://nodejs.org/api/tls.html#tls_protocol_support that describes
how this works going forward for client and server implementations.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152789"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e5420da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?278489e8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/api/tls.html#tls_protocol_support"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libuv and / or nodejs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libuv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"libuv-0.10.29-1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"nodejs-0.10.33-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libuv / nodejs");
}
