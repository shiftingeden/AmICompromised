# Roadmap

Ideas for future versions. Nothing here is built yet. Suggestions are welcome
in GitHub issues or by email (TechBitsMix@gmail.com).

## Beyond mercenary spyware: more free, open sources

iOS doesn't let any app look inside other apps or the system, so a true
virus scanner isn't possible on an iPhone. These sources fit the scans the app
already does (sysdiagnose, iPhone backup, Mac):

- [ ] **Malicious websites and servers.** Check domains and URLs found in a
      sysdiagnose or iPhone backup against free abuse.ch lists (URLhaus for
      malware sites, ThreatFox for malware command servers) and the free
      OpenPhish phishing feed.
- [ ] **Stalkerware.** Add the Echap `stalkerware-indicators` list (GitHub) for
      commercial stalkerware apps and their servers, which are far more common
      than mercenary spyware. Check first whether mvt-indicators already
      includes it, to avoid duplicates.
- [ ] **Tracking cookies (Mac Full build).** Safari cookies and history are in
      an iPhone backup, so the Full Mac build could match them against tracker
      lists such as EasyPrivacy or Disconnect. Not possible on the iPhone
      itself.
- [ ] **Mac malware.** Use ideas from Objective-See's free tools and Apple's
      built-in XProtect rules for checks against known Mac malware.

**Before adding any list:** check its licence. Some are non-commercial or
share-alike, which matters because the app takes tips. Keep everything on the
device, as today: download the lists, never upload what's scanned. The lists
would be served through the AmICompromised-data repo like the current ones, so
they update without an app release.
