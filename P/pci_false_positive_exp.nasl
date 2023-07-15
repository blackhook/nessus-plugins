#TRUSTED 029c4c3e8cff6c758b5d7b5d4615d810f747ae615627585f18863907d8c1c3a8dbdeecd4e7ebfb271fb534f5a09105cba712e589013b3d20c126e337edaf31d47685f88e3ba1ace5327832309b62cef1e00b3f49d680d4090de570e5323ec5e506bdb6fcb6b6c8344dfeb8be9d9cdd394ade0b388e2c2d316d374e74f5bcbe65afc6f17cb371b914b809f0429a5c561281aa8548a88fabdbb3d64319036c2a8fb336f8424ae13e66ef653e588535ae38f056febbf7a31fef910812daa80b7444fd7d62f0508d979b72d4089f2aa19b804fe50d937ddc69d60cdb8cd54df64e48c129c4bac5c582178a80e05ed81f50f292772b169bd6d7341921d4dabb269b1f6270acbd5ee7eb675f2fa922a7861677f9aeafe0640437b95871d8cb5dbdd5d7c7c945785069da5cc544a7afed04a2f0bb2d915a5143b94123397369b513a78e712b54216e96615e64ed1ceb88670c146da11534398b4cfde9b630f7d8922d91d4792618046410f9ec68b10182f72e6a1ae9b634a9cc836d3bd118f1b1d95c1b3e7498d94c8be8ece1d447c80c38fc7381d7394d649871fd7ed4abb0df6d5b4315307d640731dd4cd157cf83ae5f39f8a007aa68abd083bab01d3805ea29a6cc7ecc80e1f336e5be751fcbf21858b2aa61c2f2c389b877804801d737cee551b4d832abd1f0280938fe140fde62972086e8a8b8a61a708c556d0b12693ce72f88
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60020);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/04/04");
 
  script_name(english:"PCI DSS Compliance : Handling False Positives");
  script_summary(english:"How to handle false positives in PCI DSS scans.");

  script_set_attribute(attribute:"synopsis", value:
    "Notes the proper handling of false positives in PCI DSS scans."
  );
  script_set_attribute(attribute:"description", value:
"Note that per PCI Security Standards Council (PCI SSC) standards, if
the version of the remote software is known to contain flaws, a
vulnerability scanner must report it as vulnerable. The scanner must
still flag it as vulnerable, even in cases where a workaround or
mitigating configuration option is in place. This will result in the
scanner issuing false positives by PCI SSC design.

It is recommended that any workarounds and mitigating configurations
that are in place be documented including technical details, to be
presented to a third-party PCI auditor during an audit."
  );
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_end_attributes();

  script_category(ACT_END);

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Policy Compliance");
  script_require_keys("Settings/PCI_DSS", "Settings/ParanoidReport");
  script_dependencies("pci_remote_services.nasl");

  exit(0);
}

include("audit.inc");

if ( ! get_kb_item("Settings/PCI_DSS" )) audit(AUDIT_PCI);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( defined_func("nessus_get_dir") && file_stat(nessus_get_dir(N_STATE_DIR) + "/msp") > 0 )
{
  if ( hexstr(MD5(fread(nessus_get_dir(N_STATE_DIR) + "/msp"))) == "bcc7b34f215f46e783987c5f2e6199e5" )
    MSP = TRUE;
}

if ( ! MSP )
  security_note(port:0);
else exit(0, "This plugin does not run in the MSP configuration.");
