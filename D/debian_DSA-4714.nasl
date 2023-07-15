#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4714. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138066);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456", "CVE-2020-6457", "CVE-2020-6458", "CVE-2020-6459", "CVE-2020-6460", "CVE-2020-6461", "CVE-2020-6462", "CVE-2020-6463", "CVE-2020-6464", "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491", "CVE-2020-6493", "CVE-2020-6494", "CVE-2020-6495", "CVE-2020-6496", "CVE-2020-6497", "CVE-2020-6498", "CVE-2020-6505", "CVE-2020-6506", "CVE-2020-6507", "CVE-2020-6509", "CVE-2020-6831");
  script_xref(name:"DSA", value:"4714");

  script_name(english:"Debian DSA-4714-1 : chromium - security update");
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

  - CVE-2020-6423
    A use-after-free issue was found in the audio
    implementation.

  - CVE-2020-6430
    Avihay Cohen discovered a type confusion issue in the v8
    JavaScript library.

  - CVE-2020-6431
    Luan Herrera discovered a policy enforcement error.

  - CVE-2020-6432
    Luan Herrera discovered a policy enforcement error.

  - CVE-2020-6433
    Luan Herrera discovered a policy enforcement error in
    extensions.

  - CVE-2020-6434
    HyungSeok Han discovered a use-after-free issue in the
    developer tools.

  - CVE-2020-6435
    Sergei Glazunov discovered a policy enforcement error in
    extensions.

  - CVE-2020-6436
    Igor Bukanov discovered a use-after-free issue.

  - CVE-2020-6437
    Jann Horn discovered an implementation error in WebView.

  - CVE-2020-6438
    Ng Yik Phang discovered a policy enforcement error in
    extensions.

  - CVE-2020-6439
    remkoboonstra discovered a policy enforcement error.

  - CVE-2020-6440
    David Erceg discovered an implementation error in
    extensions.

  - CVE-2020-6441
    David Erceg discovered a policy enforcement error.

  - CVE-2020-6442
    B@rMey discovered an implementation error in the page
    cache.

  - CVE-2020-6443
    @lovasoa discovered an implementation error in the
    developer tools.

  - CVE-2020-6444
    mlfbrown discovered an uninitialized variable in the
    WebRTC implementation.

  - CVE-2020-6445
    Jun Kokatsu discovered a policy enforcement error.

  - CVE-2020-6446
    Jun Kokatsu discovered a policy enforcement error.

  - CVE-2020-6447
    David Erceg discovered an implementation error in the
    developer tools.

  - CVE-2020-6448
    Guang Gong discovered a use-after-free issue in the v8
    JavaScript library.

  - CVE-2020-6454
    Leecraso and Guang Gong discovered a use-after-free
    issue in extensions.

  - CVE-2020-6455
    Nan Wang and Guang Gong discovered an out-of-bounds read
    issue in the WebSQL implementation.

  - CVE-2020-6456
    Michal Bentkowski discovered insufficient validation of
    untrusted input.

  - CVE-2020-6457
    Leecraso and Guang Gong discovered a use-after-free
    issue in the speech recognizer.

  - CVE-2020-6458
    Aleksandar Nikolic discoved an out-of-bounds read and
    write issue in the pdfium library.

  - CVE-2020-6459
    Zhe Jin discovered a use-after-free issue in the
    payments implementation.

  - CVE-2020-6460
    It was discovered that URL formatting was insufficiently
    validated.

  - CVE-2020-6461
    Zhe Jin discovered a use-after-free issue.

  - CVE-2020-6462
    Zhe Jin discovered a use-after-free issue in task
    scheduling.

  - CVE-2020-6463
    Pawel Wylecial discovered a use-after-free issue in the
    ANGLE library.

  - CVE-2020-6464
    Looben Yang discovered a type confusion issue in
    Blink/Webkit.

  - CVE-2020-6465
    Woojin Oh discovered a use-after-free issue.

  - CVE-2020-6466
    Zhe Jin discovered a use-after-free issue.

  - CVE-2020-6467
    ZhanJia Song discovered a use-after-free issue in the
    WebRTC implementation.

  - CVE-2020-6468
    Chris Salls and Jake Corina discovered a type confusion
    issue in the v8 JavaScript library.

  - CVE-2020-6469
    David Erceg discovered a policy enforcement error in the
    developer tools.

  - CVE-2020-6470
    Michal Bentkowski discovered insufficient validation of
    untrusted input.

  - CVE-2020-6471
    David Erceg discovered a policy enforcement error in the
    developer tools.

  - CVE-2020-6472
    David Erceg discovered a policy enforcement error in the
    developer tools.

  - CVE-2020-6473
    Soroush Karami and Panagiotis Ilia discovered a policy
    enforcement error in Blink/Webkit.

  - CVE-2020-6474
    Zhe Jin discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2020-6475
    Khalil Zhani discovered a user interface error.

  - CVE-2020-6476
    Alexandre Le Borgne discovered a policy enforcement
    error.

  - CVE-2020-6478
    Khalil Zhani discovered an implementation error in full
    screen mode.

  - CVE-2020-6479
    Zhong Zhaochen discovered an implementation error.

  - CVE-2020-6480
    Marvin Witt discovered a policy enforcement error.

  - CVE-2020-6481
    Rayyan Bijoora discovered a policy enforcement error.

  - CVE-2020-6482
    Abdulrahman Alqabandi discovered a policy enforcement
    error in the developer tools.

  - CVE-2020-6483
    Jun Kokatsu discovered a policy enforcement error in
    payments.

  - CVE-2020-6484
    Artem Zinenko discovered insufficient validation of user
    data in the ChromeDriver implementation.

  - CVE-2020-6485
    Sergei Glazunov discovered a policy enforcement error.

  - CVE-2020-6486
    David Erceg discovered a policy enforcement error.

  - CVE-2020-6487
    Jun Kokatsu discovered a policy enforcement error.

  - CVE-2020-6488
    David Erceg discovered a policy enforcement error.

  - CVE-2020-6489
    @lovasoa discovered an implementation error in the
    developer tools.

  - CVE-2020-6490
    Insufficient validation of untrusted data was
    discovered.

  - CVE-2020-6491
    Sultan Haikal discovered a user interface error.

  - CVE-2020-6493
    A use-after-free issue was discovered in the
    WebAuthentication implementation.

  - CVE-2020-6494
    Juho Nurimen discovered a user interface error.

  - CVE-2020-6495
    David Erceg discovered a policy enforcement error in the
    developer tools.

  - CVE-2020-6496
    Khalil Zhani discovered a use-after-free issue in
    payments.

  - CVE-2020-6497
    Rayyan Bijoora discovered a policy enforcement issue.

  - CVE-2020-6498
    Rayyan Bijoora discovered a user interface error.

  - CVE-2020-6505
    Khalil Zhani discovered a use-after-free issue.

  - CVE-2020-6506
    Alesandro Ortiz discovered a policy enforcement error.

  - CVE-2020-6507
    Sergei Glazunov discovered an out-of-bounds write issue
    in the v8 JavaScript library.

  - CVE-2020-6509
    A use-after-free issue was discovered in extensions.

  - CVE-2020-6831
    Natalie Silvanovich discovered a buffer overflow issue
    in the SCTP library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6831"
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
    value:"https://www.debian.org/security/2020/dsa-4714"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the oldstable distribution (stretch), security support for
chromium has been discontinued.

For the stable distribution (buster), these problems have been fixed
in version 83.0.4103.116-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"83.0.4103.116-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"83.0.4103.116-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"83.0.4103.116-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"83.0.4103.116-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"83.0.4103.116-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"83.0.4103.116-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
