#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-15115.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(49816);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(42654, 43091, 43093, 43094, 43095, 43096, 43097, 43100, 43101, 43102, 43104, 43106, 43108, 43118);
  script_xref(name:"FEDORA", value:"2010-15115");

  script_name(english:"Fedora 13 : seamonkey-2.0.8-1.fc13 (2010-15115)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream SeaMonkey version 2.0.8, fixing multiple
security issues detailed in the upstream advisories :

http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html
#seamonkey2.0.7

Upstream release notes :

  -
    http://www.seamonkey-project.org/releases/seamonkey2.0.8
    /

    -
      http://www.seamonkey-project.org/releases/seamonkey2.0
      .7/

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html#seamonkey2.0.7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64e9a50f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.seamonkey-project.org/releases/seamonkey2.0.7/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.seamonkey-project.org/releases/seamonkey2.0.8/"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-October/049051.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?563b49f8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"seamonkey-2.0.8-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "seamonkey");
}