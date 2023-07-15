#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2436-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142633);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/19");

  script_cve_id("CVE-2020-28049");

  script_name(english:"Debian DLA-2436-1 : sddm security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that there was an issue in the sddm display manager
where local unprivileged users could create a connection to the X
server.

For Debian 9 'Stretch', this problem has been fixed in version
0.14.0-4+deb9u2.

We recommend that you upgrade your sddm packages.

For the detailed security status of sddm please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/sddm

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/sddm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/sddm"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-debian-elarun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-debian-maui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-elarun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-maldives");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sddm-theme-maui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"sddm", reference:"0.14.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-debian-elarun", reference:"0.14.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-debian-maui", reference:"0.14.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-elarun", reference:"0.14.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-maldives", reference:"0.14.0-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"sddm-theme-maui", reference:"0.14.0-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
