"""Predeclared complex-context challenges; expected labels are evaluation only."""


def challenges(reconstructions):
    specifications=[
        ("L01","S01","lsass_access"," A usable password was extracted."),
        ("L02","S01","discovery_commands"," This followed the opening of a phishing attachment."),
        ("L03","S02","payload_written"," The newly written script executed successfully."),
        ("L04","S02","failed_logons_then_success"," This proves the account was compromised."),
    ]
    for name,scenario,kind,extra in specifications:
        source=next(c for c in reconstructions[scenario].claims if c.claim_type==kind)
        yield name,source.model_copy(update={"claim_id":scenario+"-CLM-"+name,
            "claim_text":source.claim_text+extra,"related_claims":()})
