# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
# 
# Disabled on 2023/04/24 - Rejected CVE by NVD.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(148588);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/18");

  script_cve_id("CVE-2021-28421");

  script_name(english:"openSUSE Security Update : fluidsynth (openSUSE-2021-553) (deprecated)");
  script_summary(english:"Check for the openSUSE-2021-553 patch");

  script_set_attribute(attribute:"synopsis", value:
  "This plugin has been deprecated.");
  script_set_attribute(attribute:"description",value:"
** REJECT ** 
DO NOT USE THIS CANDIDATE NUMBER. 
ConsultIDs: CVE-2021-21417. 
Reason: This candidate is a duplicate of CVE-2021-21417. 
Notes: All CVE users should reference CVE-2021-21417 instead of this candidate. 
All references and descriptions in this candidate have been removed to prevent accidental usage.");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1184705"
  );
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28421");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fluidsynth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fluidsynth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fluidsynth-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fluidsynth-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfluidsynth1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfluidsynth1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfluidsynth1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfluidsynth1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}

exit(0,'CVE-2021-28421 rejected in favor of CVE-2021-21417.');
