#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-7657.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76625);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2014-2668");
  script_bugtraq_id(66474);
  script_xref(name:"FEDORA", value:"2014-7657");

  script_name(english:"Fedora 20 : couchdb-1.6.0-9.fc20 / erlang-ibrowse-4.0.1-1.fc20 (2014-7657)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - erlang-ibrowse: ver. 4.0.1

    - erlang-ibrowse: support only Fedora 18+, EL6+

    - erlang-ibrowse: added patch for CouchDB 1.6.0

    - CouchDB: ver. 1.6.0

    - CouchDB: silence stdout/stderr to prevent redundant
      flooding of /var/log/messages CouchDB already logs
      these messages to /var/log/couchdb/couch.log Instead
      print the log filename to stdout, in case a user who
      ran it from the CLI is confused about where the
      messages went.

    - CouchDB: -couch_ini accepts .ini or a .d/ directory.
      For directories it reads any *.ini file. Fixes
      #1002277.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1082168"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135679.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?576706fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c128f39e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected couchdb and / or erlang-ibrowse packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:couchdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:erlang-ibrowse");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"couchdb-1.6.0-9.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"erlang-ibrowse-4.0.1-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "couchdb / erlang-ibrowse");
}
