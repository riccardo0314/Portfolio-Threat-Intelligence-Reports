rule NCG_HCC_PhishingKit {
    meta:
        author = "RC"
        description = "Detects the HTML source code of the fake Heritage Community Credit Union or Netcapital Globe phishing kits"
        date = "2026-02-26"
        target_domain = "heritagecommunitycredit[.]com, netcapitalglobe[.]com" 
        threat_type = "Credential Harvesting / Financial Fraud"

    strings:
        // --- KIT 1: HCCU ---
        $hccu_title = "<title>HCCU - Home</title>" nocase
        $hccu_text = "Transforming banking through intelligent technology" nocase
        $tech_livewire = "livewire" nocase
        $tech_alpine = "alpine.js" nocase
        
        // --- KIT 2: NET CAPITAL GLOBE ---
        $ncg_title = "Net Capital Globe - Built for investors" nocase 
        $ncg_text = "NET CAPITAL GLOBE INVESTMENTS" nocase
        $tech_particle = "particles.js" nocase
        $tech_smartsupp = "smartsupp" nocase
        
        $action_login = "Login" nocase
        $action_create = "Create Account" nocase
        $action_create2 = "CREATE AN ACCOUNT" nocase

    condition:
        (
            $hccu_title and $hccu_text and ($tech_livewire or $tech_alpine) and ($action_login or $action_create or $action_create2)
        )
        or
        (
            $ncg_title and $ncg_text and ($tech_particle or $tech_smartsupp) and ($action_login or $action_create or $action_create2)
        )
}
