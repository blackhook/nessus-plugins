#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2650-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149345);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/06");

  script_cve_id("CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28009", "CVE-2020-28011", "CVE-2020-28012", "CVE-2020-28013", "CVE-2020-28014", "CVE-2020-28015", "CVE-2020-28017", "CVE-2020-28019", "CVE-2020-28020", "CVE-2020-28021", "CVE-2020-28022", "CVE-2020-28023", "CVE-2020-28024", "CVE-2020-28025", "CVE-2020-28026");
  script_xref(name:"IAVA", value:"2021-A-0216-S");

  script_name(english:"Debian DLA-2650-1 : exim4 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Qualys Research Labs reported several vulnerabilities in Exim, a
mail transport agent, which could result in local privilege escalation
and remote code execution.

Details can be found in the Qualys advisory at
https://www.qualys.com/2021/05/04/21nails/21nails.txt

For Debian 9 stretch, these problems have been fixed in version
4.89-2+deb9u8.

We recommend that you upgrade your exim4 packages.

For the detailed security status of exim4 please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/exim4

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/exim4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qualys.com/2021/05/04/21nails/21nails.txt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28026");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-heavy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-heavy-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-light");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-daemon-light-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exim4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eximon4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"exim4", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-base", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-config", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-heavy-dbg", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-daemon-light-dbg", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dbg", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"exim4-dev", reference:"4.89-2+deb9u8")) flag++;
if (deb_check(release:"9.0", prefix:"eximon4", reference:"4.89-2+deb9u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
