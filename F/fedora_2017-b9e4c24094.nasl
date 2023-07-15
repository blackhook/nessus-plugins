#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-b9e4c24094.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102276);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"FEDORA", value:"2017-b9e4c24094");

  script_name(english:"Fedora 25 : subversion (2017-b9e4c24094)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest stable release of _Apache Subversion_,
version **1.9.6**.

### User-visible changes: #### Client-side bugfixes :

  - cp/mv: improve error message when target is an
    unversioned dir 

  - merge: reduce memory usage with large amounts of
    mergeinfo ([issue
    4667](https://issues.apache.org/jira/browse/SVN-4667))
    #### Server-side bugfixes :

  - 'svnadmin freeze': document the purpose more clearly 

  - dump: fix segfault when a revision has no revprops 

  - fsfs: improve error message upon failure to open
    rep-cache 

  - fsfs: never attempt to share directory representations 

  - fsfs: make consistency independent of hash algorithms
    &#9;This change makes Subversion resilient to collision
    attacks, including &#9;SHA-1 collision attacks such as
    http://shattered.io/. See also our &#9;documentation at
    https://subversion.apache.org/faq#shattered-sha1 and
    https://subversion.apache.org/docs/release-notes/1.9#sha
    ttered-sha1. #### Client-side and server-side bugfixes :

  - work around an APR bug related to file truncation ####
    Bindings bugfixes :

  - javahl: follow redirects when opening a connection

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://shattered.io/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-b9e4c24094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://subversion.apache.org/faq#shattered-sha1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:25");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^25([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 25", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC25", reference:"subversion-1.9.6-2.fc25")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
