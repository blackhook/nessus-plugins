#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-8535.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40600);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(35370, 35371, 35372, 35373, 35377, 35380, 35383, 35461);
  script_xref(name:"FEDORA", value:"2009-8535");

  script_name(english:"Fedora 11 : thunderbird-3.0-2.6.b3.fc11 (2009-8535)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to upstream version 3.0 Beta3. It includes security fixes
recently fixed in stable Thunderbird 2.x and Firefox/Gecko security
fixes:
http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.ht
ml
http://www.mozilla.org/security/known-vulnerabilities/firefox30.html

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox30.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7d74da4"
  );
  # http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?280be806"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-August/027875.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f7ebc7b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/18");
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
if (! ereg(pattern:"^11([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 11.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC11", reference:"thunderbird-3.0-2.6.b3.fc11")) flag++;


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
