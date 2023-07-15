#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-220.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133757);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2019-15613", "CVE-2019-15621", "CVE-2019-15623", "CVE-2019-15624", "CVE-2020-8118", "CVE-2020-8119");

  script_name(english:"openSUSE Security Update : nextcloud (openSUSE-2020-220)");
  script_summary(english:"Check for the openSUSE-2020-220 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nextcloud fixes the following issues :

Nextcloud was updated to 15.0.14 :

  - NC-SA-2020-002, CVE-2019-15613: workflow rules to depend
    their behaviour on the file extension when checking file
    mimetypes (boo#1162766)

  - NC-SA-2019-016, CVE-2019-15623: Exposure of Private
    Information caused the server to send it's domain and
    user IDs to the Nextcloud Lookup Server without any
    further data when the Lookup server is disabled
    (boo#1162775)

  - NC-SA-2019-015, CVE-2019-15624: Improper Input
    Validation allowed group admins to create users with IDs
    of system folders (boo#1162776)

  - NC-SA-2019-012, CVE-2020-8119: Improper authorization
    caused leaking of previews and files when a file-drop
    share link is opened via the gallery app (boo#1162781)

  - NC-SA-2019-014, CVE-2020-8118: An authenticated
    server-side request forgery allowed to detect local and
    remote services when adding a new subscription in the
    calendar application (boo#1162782)

  - NC-SA-2020-012, CVE-2019-15621: Improper permissions
    preservation causes sharees to be able to reshare with
    write permissions when sharing the mount point of a
    share they received, as a public link (boo#1162784)

  - To many changes. For detail see:
    https://nextcloud.com/changelog/

nextcloud was updated to 13.0.12 :

  - Fix NC-SA-2020-001

  - To many changes. For detail see:
    https://nextcloud.com/changelog/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1162784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nextcloud.com/changelog/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nextcloud package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nextcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"nextcloud-15.0.14-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nextcloud");
}
