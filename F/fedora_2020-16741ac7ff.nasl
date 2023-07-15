#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-16741ac7ff.
#

include("compat.inc");

if (description)
{
  script_id(139256);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/24");

  script_cve_id("CVE-2020-12402");
  script_xref(name:"FEDORA", value:"2020-16741ac7ff");

  script_name(english:"Fedora 31 : nspr / nss (2020-16741ac7ff)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updates the nspr and nss package to upstream NSPR 4.26 and NSS 3.54.

For details about new functionality and a list of bugs fixed in this
release please see the upstream release notes :

- https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.54_release_notes

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-16741ac7ff"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.54_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae2cff3d"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12402");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:31");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^31([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 31", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC31", reference:"nspr-4.26.0-1.fc31")) flag++;
if (rpm_check(release:"FC31", reference:"nss-3.54.0-1.fc31")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nss");
}
