import SwiftUI

/// Who published the lists the app checks against, with links. Shared by the
/// iPhone and Mac Indicator Sources screens.
struct SourceCredits: View {
    var body: some View {
        Section {
            link("Mobile Verification Toolkit indicators (Amnesty International)", "https://github.com/mvt-project/mvt-indicators")
            link("CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
        } header: {
            Text("Credits")
        } footer: {
            Text("The main spyware lists and the exploited-bug list.")
        }

        Section {
            link("Amnesty International investigations", "https://github.com/AmnestyTech/investigations")
            link("Citizen Lab malware indicators", "https://github.com/citizenlab/malware-indicators")
            link("Citizen Lab: Exposing AdFection (2026)", "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/")
            link("Confiant: ADINT, weaponized ad tech (2026)", "https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming")
            link("Zero Breach Toolkit (AdFection list, CC0)", "https://github.com/interplains/Zero-Breach-Toolkit")
            link("How the extra lists are built", "https://github.com/shiftingeden/AmICompromised-data")
        } header: {
            Text("Extra lists credits")
        } footer: {
            Text("The AdFection list was compiled from Citizen Lab and Confiant research by the independent Zero Breach Toolkit project and released into the public domain. These organisations don't endorse this app.")
        }
    }

    private func link(_ title: String, _ url: String) -> some View {
        Link(title, destination: URL(string: url)!)
    }
}
