rule HCCU_CreditUnion_PhishingKit {
    meta:
        author = "RC"
        description = "Detects the HTML source code of the fake Heritage Community Credit Union phishing kit"
        date = "2026-02-26"
        target_domain = "heritagecommunitycredit[.]com"
        threat_type = "Credential Harvesting / Financial Fraud"

    strings:
        $lure_title = "<title>HCCU - Home</title>" nocase
        $lure_text = "Transforming banking through intelligent technology" nocase
        
        $tech_livewire = "livewire" nocase
        $tech_alpine = "alpine.js" nocase
        
        $action_login = "Login" 
        $action_create = "Create Account"

    condition:

        $lure_title and $lure_text and ($tech_livewire or $tech_alpine) and ($action_login or $action_create)
}
