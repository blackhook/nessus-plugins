#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4340. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119018);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2018-17478");
  script_xref(name:"DSA", value:"4340");

  script_name(english:"Debian DSA-4340-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An out-of-bounds bounds memory access issue was discovered in
chromium's v8 JavaScript library by cloudfuzzer.

This update also fixes two problems introduced by the previous
security upload. Support for arm64 has been restored and gconf-service
is no longer a package dependency."
  );
  # https://security-tracker.debian.org/tracker/source-package/chromium-browser
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33901a2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4340"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (stretch), this problem has been fixed in
version 70.0.3538.102-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"70.0.3538.102-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"70.0.3538.102-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"70.0.3538.102-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"70.0.3538.102-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"70.0.3538.102-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"70.0.3538.102-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
