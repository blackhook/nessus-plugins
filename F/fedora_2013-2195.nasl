#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-2195.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64677);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(57849);
  script_xref(name:"FEDORA", value:"2013-2195");

  script_name(english:"Fedora 18 : roundcubemail-0.8.5-1.fc18 (2013-2195)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cross-site scripting (XSS) flaws were round in the way Round Cube
Webmail, a browser-based multilingual IMAP client, performed
sanitization of 'data' and 'vbscript' URLs. A remote attacker could
provide a specially crafted URL that, when opened would lead to
arbitrary JavaScript, VisualBasic script or HTML code execution in the
context of Round Cube Webmail's user session.

Upstream ticket: [1] http://trac.roundcube.net/ticket/1488850

Further details: [2]
http://trac.roundcube.net/attachment/ticket/1488850/RoundCube2XSS.pdf

Upstream patch: [3]
https://github.com/roundcube/roundcubemail/commit/74cd0a9b62f11bc07c5a
1d3ba0098b54883eb0ba

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://sourceforge.net/news/?group_id=139281&id=310213
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cea87f57"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://trac.roundcube.net/attachment/ticket/1488850/RoundCube2XSS.pdf"
  );
  # http://trac.roundcube.net/ticket/1488850
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/roundcube/roundcubemail/issues/4033"
  );
  # http://www.openwall.com/lists/oss-security/2013/02/07/11
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2013/02/07/11"
  );
  # http://www.openwall.com/lists/oss-security/2013/02/08/1
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2013/02/08/1"
  );
  # https://github.com/roundcube/roundcubemail/commit/74cd0a9b62f11bc07c5a1d3ba0098b54883eb0ba
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0c5438d1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-February/098877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ff7f686"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/19");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"roundcubemail-0.8.5-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
