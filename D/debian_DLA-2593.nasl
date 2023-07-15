#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2593-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(147775);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/15");

  script_name(english:"Debian DLA-2593-1 : ca-certificates whitelist Symantec CA");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update reverts the Symantec CA blacklist (which was originally
#911289). The following root certificates were added back (+) :

  + 'GeoTrust Global CA'

  + 'GeoTrust Primary Certification Authority'

  + 'GeoTrust Primary Certification Authority - G2'

  + 'GeoTrust Primary Certification Authority - G3'

  + 'GeoTrust Universal CA'

  + 'thawte Primary Root CA'

  + 'thawte Primary Root CA - G2'

  + 'thawte Primary Root CA - G3'

  + 'VeriSign Class 3 Public Primary Certification Authority
    - G4'

  + 'VeriSign Class 3 Public Primary Certification Authority
    - G5'

  + 'VeriSign Universal Root Certification Authority'

NOTE: due to bug #743339, CA certificates added back in this version
won't automatically be trusted again on upgrade. Affected users may
need to reconfigure the package to restore the desired state.

For Debian 9 stretch, this problem has been fixed in version
20200601~deb9u2.

We recommend that you upgrade your ca-certificates packages.

For the detailed security status of ca-certificates please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/ca-certificates

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/03/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ca-certificates"
  );
  # https://security-tracker.debian.org/tracker/source-package/ca-certificates
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9932d96"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ca-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ca-certificates-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"ca-certificates", reference:"20200601~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"ca-certificates-udeb", reference:"20200601~deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
