#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4562. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130774);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-13659", "CVE-2019-13660", "CVE-2019-13661", "CVE-2019-13662", "CVE-2019-13663", "CVE-2019-13664", "CVE-2019-13665", "CVE-2019-13666", "CVE-2019-13667", "CVE-2019-13668", "CVE-2019-13669", "CVE-2019-13670", "CVE-2019-13671", "CVE-2019-13673", "CVE-2019-13674", "CVE-2019-13675", "CVE-2019-13676", "CVE-2019-13677", "CVE-2019-13678", "CVE-2019-13679", "CVE-2019-13680", "CVE-2019-13681", "CVE-2019-13682", "CVE-2019-13683", "CVE-2019-13685", "CVE-2019-13686", "CVE-2019-13687", "CVE-2019-13688", "CVE-2019-13691", "CVE-2019-13692", "CVE-2019-13693", "CVE-2019-13694", "CVE-2019-13695", "CVE-2019-13696", "CVE-2019-13697", "CVE-2019-13699", "CVE-2019-13700", "CVE-2019-13701", "CVE-2019-13702", "CVE-2019-13703", "CVE-2019-13704", "CVE-2019-13705", "CVE-2019-13706", "CVE-2019-13707", "CVE-2019-13708", "CVE-2019-13709", "CVE-2019-13710", "CVE-2019-13711", "CVE-2019-13713", "CVE-2019-13714", "CVE-2019-13715", "CVE-2019-13716", "CVE-2019-13717", "CVE-2019-13718", "CVE-2019-13719", "CVE-2019-13720", "CVE-2019-13721", "CVE-2019-5869", "CVE-2019-5870", "CVE-2019-5871", "CVE-2019-5872", "CVE-2019-5874", "CVE-2019-5875", "CVE-2019-5876", "CVE-2019-5877", "CVE-2019-5878", "CVE-2019-5879", "CVE-2019-5880");
  script_xref(name:"DSA", value:"4562");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CEA-ID", value:"CEA-2019-0698");

  script_name(english:"Debian DSA-4562-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2019-5869
    Zhe Jin discovered a use-after-free issue.

  - CVE-2019-5870
    Guang Gong discovered a use-after-free issue.

  - CVE-2019-5871
    A buffer overflow issue was discovered in the skia
    library.

  - CVE-2019-5872
    Zhe Jin discovered a use-after-free issue.

  - CVE-2019-5874
    James Lee discovered an issue with external Uniform
    Resource Identifiers.

  - CVE-2019-5875
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2019-5876
    Man Yue Mo discovered a use-after-free issue.

  - CVE-2019-5877
    Guang Gong discovered an out-of-bounds read issue.

  - CVE-2019-5878
    Guang Gong discovered an use-after-free issue in the v8
    JavaScript library.

  - CVE-2019-5879
    Jinseo Kim discover that extensions could read files on
    the local system.

  - CVE-2019-5880
    Jun Kokatsu discovered a way to bypass the SameSite
    cookie feature.

  - CVE-2019-13659
    Lnyas Zhang discovered a URL spoofing issue.

  - CVE-2019-13660
    Wenxu Wu discovered a user interface error in full
    screen mode.

  - CVE-2019-13661
    Wenxu Wu discovered a user interface spoofing issue in
    full screen mode.

  - CVE-2019-13662
    David Erceg discovered a way to bypass the Content
    Security Policy.

  - CVE-2019-13663
    Lnyas Zhang discovered a way to spoof Internationalized
    Domain Names.

  - CVE-2019-13664
    Thomas Shadwell discovered a way to bypass the SameSite
    cookie feature.

  - CVE-2019-13665
    Jun Kokatsu discovered a way to bypass the multiple file
    download protection feature.

  - CVE-2019-13666
    Tom Van Goethem discovered an information leak.

  - CVE-2019-13667
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2019-13668
    David Erceg discovered an information leak.

  - CVE-2019-13669
    Khalil Zhani discovered an authentication spoofing
    issue.

  - CVE-2019-13670
    Guang Gong discovered a memory corruption issue in the
    v8 JavaScript library.

  - CVE-2019-13671
    xisigr discovered a user interface error.

  - CVE-2019-13673
    David Erceg discovered an information leak.

  - CVE-2019-13674
    Khalil Zhani discovered a way to spoof Internationalized
    Domain Names.

  - CVE-2019-13675
    Jun Kokatsu discovered a way to disable extensions.

  - CVE-2019-13676
    Wenxu Wu discovered an error in a certificate warning.

  - CVE-2019-13677
    Jun Kokatsu discovered an error in the chrome web store.

  - CVE-2019-13678
    Ronni Skansing discovered a spoofing issue in the
    download dialog window.

  - CVE-2019-13679
    Conrad Irwin discovered that user activation was not
    required for printing.

  - CVE-2019-13680
    Thijs Alkamade discovered an IP address spoofing issue.

  - CVE-2019-13681
    David Erceg discovered a way to bypass download
    restrictions.

  - CVE-2019-13682
    Jun Kokatsu discovered a way to bypass the site
    isolation feature.

  - CVE-2019-13683
    David Erceg discovered an information leak.

  - CVE-2019-13685
    Khalil Zhani discovered a use-after-free issue.

  - CVE-2019-13686
    Brendon discovered a use-after-free issue.

  - CVE-2019-13687
    Man Yue Mo discovered a use-after-free issue.

  - CVE-2019-13688
    Man Yue Mo discovered a use-after-free issue.

  - CVE-2019-13691
    David Erceg discovered a user interface spoofing issue.

  - CVE-2019-13692
    Jun Kokatsu discovered a way to bypass the Same Origin
    Policy.

  - CVE-2019-13693
    Guang Gong discovered a use-after-free issue.

  - CVE-2019-13694
    banananapenguin discovered a use-after-free issue.

  - CVE-2019-13695
    Man Yue Mo discovered a use-after-free issue.

  - CVE-2019-13696
    Guang Gong discovered a use-after-free issue in the v8
    JavaScript library.

  - CVE-2019-13697
    Luan Herrera discovered an information leak.

  - CVE-2019-13699
    Man Yue Mo discovered a use-after-free issue.

  - CVE-2019-13700
    Man Yue Mo discovered a buffer overflow issue.

  - CVE-2019-13701
    David Erceg discovered a URL spoofing issue.

  - CVE-2019-13702
    Phillip Langlois and Edward Torkington discovered a
    privilege escalation issue in the installer.

  - CVE-2019-13703
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2019-13704
    Jun Kokatsu discovered a way to bypass the Content
    Security Policy.

  - CVE-2019-13705
    Luan Herrera discovered a way to bypass extension
    permissions.

  - CVE-2019-13706
    pdknsk discovered an out-of-bounds read issue in the
    pdfium library.

  - CVE-2019-13707
    Andrea Palazzo discovered an information leak.

  - CVE-2019-13708
    Khalil Zhani discovered an authentication spoofing
    issue.

  - CVE-2019-13709
    Zhong Zhaochen discovered a way to bypass download
    restrictions.

  - CVE-2019-13710
    bernardo.mrod discovered a way to bypass download
    restrictions.

  - CVE-2019-13711
    David Erceg discovered an information leak.

  - CVE-2019-13713
    David Erceg discovered an information leak.

  - CVE-2019-13714
    Jun Kokatsu discovered an issue with Cascading Style
    Sheets.

  - CVE-2019-13715
    xisigr discovered a URL spoofing issue.

  - CVE-2019-13716
    Barron Hagerman discovered an error in the service
    worker implementation.

  - CVE-2019-13717
    xisigr discovered a user interface spoofing issue.

  - CVE-2019-13718
    Khalil Zhani discovered a way to spoof Internationalized
    Domain Names.

  - CVE-2019-13719
    Khalil Zhani discovered a user interface spoofing issue.

  - CVE-2019-13720
    Anton Ivanov and Alexey Kulaev discovered a
    use-after-free issue.

  - CVE-2019-13721
    banananapenguin discovered a use-after-free issue in the
    pdfium library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5869"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4562"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the oldstable distribution (stretch), support for chromium has
been discontinued. Please upgrade to the stable release (buster) to
continue receiving chromium updates or switch to firefox, which
continues to be supported in the oldstable release.

For the stable distribution (buster), these problems have been fixed
in version 78.0.3904.97-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5878");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"chromium", reference:"78.0.3904.97-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"78.0.3904.97-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"78.0.3904.97-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"78.0.3904.97-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"78.0.3904.97-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"78.0.3904.97-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
