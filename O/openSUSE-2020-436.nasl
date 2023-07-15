#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-436.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(135162);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/06");

  script_cve_id("CVE-2019-14751");

  script_name(english:"openSUSE Security Update : python-nltk (openSUSE-2020-436)");
  script_summary(english:"Check for the openSUSE-2020-436 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-nltk fixes the following issues :

Update to 3.4.5 (boo#1146427, CVE-2019-14751) :

  - CVE-2019-14751: Fixed Zip slip vulnerability in
    downloader for the unlikely situation where a user
    configures their downloader to use a compromised server
    (boo#1146427)

Update to 3.4.4 :

  - fix bug in plot function (probability.py)

  - add improved PanLex Swadesh corpus reader

  - add Text.generate()

  - add QuadgramAssocMeasures

  - add SSP to tokenizers

  - return confidence of best tag from AveragedPerceptron

  - make plot methods return Axes objects

  - don't require list arguments to
    PositiveNaiveBayesClassifier.train

  - fix Tree classes to work with native Python copy library

  - fix inconsistency for NomBank

  - fix random seeding in LanguageModel.generate

  - fix ConditionalFreqDist mutation on tabulate/plot call

  - fix broken links in documentation

  - fix misc Wordnet issues

  - update installation instructions

Version update to 3.4.1 :

  - add chomsky_normal_form for CFGs

  - add meteor score

  - add minimum edit/Levenshtein distance based alignment
    function

  - allow access to collocation list via
    text.collocation_list()

  - support corenlp server options

  - drop support for Python 3.4

  - other minor fixes

Update to v3.4 :

  - Support Python 3.7

  - New Language Modeling package

  - Cistem Stemmer for German

  - Support Russian National Corpus incl POS tag model

  - Krippendorf Alpha inter-rater reliability test

  - Comprehensive code clean-ups

  - Switch continuous integration from Jenkins to Travis

Updated to v3.3 :

  - Support Python 3.6

  - New interface to CoreNLP

  - Support synset retrieval by sense key

  - Minor fixes to CoNLL Corpus Reader

  - AlignedSent

  - Fixed minor inconsistencies in APIs and API
    documentation

  - Better conformance to PEP8

  - Drop Moses Tokenizer (incompatible license)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1146427"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-nltk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-nltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-nltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");
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

if ( rpm_check(release:"SUSE15.1", reference:"python2-nltk-3.4.5-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-nltk-3.4.5-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-nltk / python3-nltk");
}
