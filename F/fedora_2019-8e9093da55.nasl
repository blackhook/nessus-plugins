#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-8e9093da55.
#

include("compat.inc");

if (description)
{
  script_id(131713);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id("CVE-2019-10195", "CVE-2019-14867");
  script_xref(name:"FEDORA", value:"2019-8e9093da55");

  script_name(english:"Fedora 30 : freeipa (2019-8e9093da55)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"FreeIPA 4.8.3 is a security update release that includes fixes for two
issues :

  - CVE-2019-10195: Don't log passwords embedded in commands
    in calls using batch A flaw was found in the way that
    FreeIPA's batch processing API logged operations. This
    included passing user passwords in clear text on FreeIPA
    masters. Batch processing of commands with passwords as
    arguments or options is not performed by default in
    FreeIPA but is possible by third-party components. An
    attacker having access to system logs on FreeIPA masters
    could use this flaw to produce log file content with
    passwords exposed. The issue was reported by Jamison
    Bennett from Cloudera

  - CVE-2019-14867: Make sure to have storage space for tag
    A flaw was found in the way the internal function
    ber_scanf() was used in some components of the IPA
    server, which parsed kerberos key data. An
    unauthenticated attacker who could trigger parsing of
    the krb principal key could cause the IPA server to
    crash or in some conditions, cause arbitrary code to be
    executed on the server hosting the IPA server. The issue
    was reported by Todd Lipcon from Cloudera

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-8e9093da55"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freeipa package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14867");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:freeipa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"freeipa-4.8.3-1.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeipa");
}
