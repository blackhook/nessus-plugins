#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2154.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(129095);
  script_version("1.1");
  script_cvs_date("Date: 2019/09/20  9:30:10");

  script_name(english:"openSUSE Security Update : opera (openSUSE-2019-2154)");
  script_summary(english:"Check for the openSUSE-2019-2154 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for opera fixes the following issues :

Opera was updated to version 63.0.3368.88 :

  - DNA-79103 Saving link to bookmarks saves it to Other
    bookmarks folder

  - DNA-79455 Crash at views::MenuController::
    FindNextSelectableMenuItem(views::MenuItemView*, int,
    views:: MenuController::SelectionIncrementDirectionType,
    bool)

  - DNA-79579 Continuous packages using
    new_mac_bundle_structure do not run

  - DNA-79611 Update opauto_paths.py:GetResourcesDir

  - DNA-79621 Add support for new bundle structure to old
    autoupdate clients

  - DNA-80131 Sign Opera Helper(GPU).app
    opera_components/tracking_data/tracking_data_paths.cc

  - DNA-80638 Cherry-pick fix for CreditCardTest.
    UpdateFromImportedCard_ExpiredVerifiedCardUpdatedWithSam
    eName

  - DNA-80801 Very slow tab deletion process"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected opera package.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"opera-63.0.3368.88-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera");
}
