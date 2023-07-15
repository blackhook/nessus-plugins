#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-455803056d.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110426);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2018-10847");
  script_xref(name:"FEDORA", value:"2018-455803056d");

  script_name(english:"Fedora 27 : prosody (2018-455803056d)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Prosody 0.10.2 ==============

See upstream's blog post at
https://blog.prosody.im/prosody-0-10-2-security-release/ for a full
overview of the release changes.

Prosody 0.10.2 fixes a cross-host authentication vulnerability,
CVE-2018-10847. The issue affects Prosody instances that have multiple
virtual hosts (including anonymous authenticated hosts). All versions
of Prosody before 0.9.14 and 0.10.2 are affected. A full security
advisory is available at https://prosody.im/security/advisory_20180531

Security

--------

  - mod_c2s: Do not allow the stream &lsquo;to&rsquo; to
    change across stream restarts (fixes #1147)

Minor changes

-------------

  - mod_websocket: Store the request object on the session
    for use by other modules (fixes #1153)

  - mod_c2s: Avoid concatenating potential nil value (fixes
    #753)

  - core.certmanager: Allow all non-whitespace in service
    name (fixes #1019)

  - mod_disco: Skip code specific to disco on user accounts
    (avoids invoking usermanager, fixes #1150)

  - mod_bosh: Store the normalized hostname on session
    (fixes #1151)

  - MUC: Fix error logged when no persistent rooms present
    (fixes #1154)

Dowstream

----------

  - Changed log rotation from weekly/52 to local system
    defaults

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blog.prosody.im/prosody-0-10-2-security-release/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-455803056d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected prosody package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:prosody");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"prosody-0.10.2-1.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "prosody");
}
